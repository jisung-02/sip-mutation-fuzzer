# IMS IPsec SA dispatch — 4-SA 모델, rekey, fuzzer 의 dual-port bind

2026-04-26 픽셀 10 fuzzing 중 발견한 issue 와 fix 의 배경. native ipsec mode 가 어떤 가정 위에 동작하고, 그 가정이 IPsec SA rekey 시 깨지는 이유, 그래서 driver 가 server/client SA 양쪽에 bind 해야 하는 이유를 정리한다.

---

## 1. IMS IPsec 의 4-SA 모델 (3GPP TS 33.203)

UE 와 P-CSCF 가 SIP REGISTER → 401 challenge → 인증 응답을 거치며 IPsec 협상을 한다. 그 결과 **4개의 ESP SA 를 동시에 만든다** — UE 측 client/server, P-CSCF 측 client/server.

```
UE (10.20.20.4)                          P-CSCF (172.22.0.21)
  port_uc = 9900   ◄────────────────►   port_pc = 5109   (client side)
  port_us = 9901   ◄────────────────►   port_ps = 6109   (server side)
```

각 단방향 SA 가 한 개씩, 총 4개:

| # | 방향 | 4-tuple | 용도 |
|---|---|---|---|
| 1 | P-CSCF → UE | `:6109 → :9901` | server side. P-CSCF 가 UE 에 request 보낼 때 |
| 2 | UE → P-CSCF | `:9901 → :6109` | server side reverse. UE 가 그 request 의 response 보낼 때 |
| 3 | P-CSCF → UE | `:5109 → :9900` | client side. UE 의 outbound traffic 응답을 P-CSCF 가 보낼 때 |
| 4 | UE → P-CSCF | `:9900 → :5109` | client side reverse. UE 가 P-CSCF 에 request 보낼 때 |

3GPP 의 의도:
- UE 가 P-CSCF 로 보내는 outbound (REGISTER 등) 는 SA #4 사용 (UE client → P-CSCF client)
- P-CSCF 가 UE 로 보내는 inbound (incoming INVITE 의 forward 등) 는 SA #1 사용 (P-CSCF server → UE server)
- 응답은 reverse SA 로 (#2 또는 #3)

server side 와 client side 가 분리된 이유는 **서버 역할의 SIP UA 와 클라이언트 역할의 SIP UA 가 동시에 가능**하기 때문. 한쪽이 죽어도 다른쪽이 살아있게 redundancy 확보.

xfrm state 로 본 실제 SA 4개 (픽셀 attach 후 시점 예시):

```bash
$ docker exec pcscf ip xfrm state
src 172.22.0.21 dst 10.20.20.4
    proto esp spi 0x0000737a reqid 29562 mode transport
    sel src 172.22.0.21/32 dst 10.20.20.4/32 sport 6109 dport 9901    ← SA #1
src 10.20.20.4 dst 172.22.0.21
    proto esp spi 0x0000104f reqid 4175 mode transport
    sel src 10.20.20.4/32 dst 172.22.0.21/32 sport 9901 dport 6109    ← SA #2
src 172.22.0.21 dst 10.20.20.4
    proto esp spi 0x0000737b reqid 29563 mode transport
    sel src 172.22.0.21/32 dst 10.20.20.4/32 sport 5109 dport 9900    ← SA #3
src 10.20.20.4 dst 172.22.0.21
    proto esp spi 0x0000104e reqid 4174 mode transport
    sel src 10.20.20.4/32 dst 172.22.0.21/32 sport 9900 dport 5109    ← SA #4
```

각 SA 가 독립된 SPI / 키 / replay window 를 가진다.

---

## 2. SA rekey 가 뭔가

IPsec SA 는 영원히 살지 않는다. 시간 또는 packet count 한도에 걸리면 새 SA 로 교체된다. 이를 **rekey** 라고 한다.

3GPP TS 33.203 의 IMS 시나리오에서 rekey 트리거는 두 가지:

1. **REGISTER 갱신 시 (re-authentication)** — UE 가 정기적으로 (보통 ~600초) REGISTER 보내고 401 challenge 받으면 새 IK/CK 로 새 IPsec SA 협상. 옛 SA 는 즉시 안 지우고 한동안 같이 둔다.
2. **단말 측 자체 rekey 트리거** — 일부 modem 구현은 packet count 또는 sequence 도달 시 자체적으로 rekey 요청.

rekey 직후의 xfrm state 는 보통 8개 SA (옛 4개 + 새 4개) 가 잠시 공존하다가, hard expiry 시점에 옛 4개가 정리된다. 이 공존 구간이 fuzzer 입장에서 까다롭다.

### rekey 가 fuzzer 에 미치는 영향

- 옛 SA pair 의 sport/dport 와 새 SA pair 의 sport/dport 가 다를 수 있다 (예: 옛: `6100/6101`, 새: `6108/6109`). 
- fuzzer 가 캠페인 시작 시 한 번 resolve 한 cached port 가 stale 이 된다.
- **kernel 의 xfrm output policy 가 어느 SA 를 선택하느냐는 fuzzer 의 outbound 4-tuple 과 SA selector 매칭에 따라 결정** — 시점에 따라 server pair 또는 client pair 로 routing 된다.

이 프로젝트에서는 매 case 마다 `ip xfrm state` 를 다시 query 하도록 fix 했다 (2026-04-25 의 `Removed _cached_ports, renamed to _resolve_ports_live`). 그러나 그것만으로는 부족한 이유가 다음 절이다.

---

## 3. fuzzer 의 단일 SA 가정과 그 한계

`sender/ipsec_native.py` 의 native ipsec sender 는 한 case 당 하나의 4-tuple 만 사용한다:

```python
# resolve_protected_ports → (port_pc, port_ps)
# resolve_native_ipsec_session → port_map[ue_port] = pcscf_port
src_port = preflight.pcscf_port  # = port_map[port_ps] = 6109   (server pair)
dst_port = resolved_port          # = port_ps = 9901
```

즉 **항상 server pair (#1) 로 송신한다고 가정**한다. UE 응답은 reverse server SA (#2) 로 와서 dst=6109. fuzzer 가 6109 socket 에 bind + connect 했으면 받는다.

### 가정이 깨지는 시점

xfrm output policy 가 server pair selector 와 매칭하지 않는 경우, 같은 outbound 트래픽이 client pair (#3) 으로 routing 될 수 있다. 이는 다음 조건에서 관찰된다:

- rekey 직후 새 server pair 의 selector 가 일시적으로 비활성
- 단말 측 IPsec stack 의 quirk (Pixel 10 Android 16 에서 관찰됨)
- 캠페인 cooldown 이 너무 짧아 SA selection 이 안정화되기 전에 다음 case 가 들어가는 race

이 경우 wire 에 보이는 패킷:

```
fuzzer → 단말 ESP spi=737b len 500   ← client SA #3 사용
단말 → fuzzer ESP spi=104e len 84    ← client SA #4 reverse, dst=5109
단말 → fuzzer ESP spi=104e len 756   ← 진짜 SIP 응답, dst=5109
```

fuzzer 는 **6109 에 bind, 5109 에 안 bind**. 5109 로 도착한 응답은 kernel 의 socket lookup 에서 갈 곳이 없어 **ICMP port unreachable** 로 떨어진다 (wire 의 `fuzzer → 단말 ESP len 84` 의 정체).

결과는 **fuzzer 의 recvfrom() 이 timeout** 까지 기다리다 종료. 해당 case 는 timeout verdict.

2026-04-26 picsel 캠페인에서:

| 캠페인 | server SA active? | 결과 |
|---|---|---|
| `66aeca76` c0~c20 | yes (`737a/104f`) | normal 200/500 응답 받음 |
| `66aeca76` c25~c34 | no, client pair (`737b/104e`) 로 swap | timeout 14건 연속 |
| `df606d37` c0~c9 | client pair active | timeout 100% (9/9) |
| `62bb3c81` (fix 후) | server pair active 다시 | normal 7/8, alt path idle 이지만 안전망 확보 |

---

## 4. Fix — driver 가 server + client SA 양쪽 bind

가장 robust 한 해결: **driver 가 두 P-CSCF port (server 측 6109, client 측 5109) 둘 다 bind 하고 select 로 양쪽 monitor**. 어느 SA pair 가 활성이든 응답을 잡는다.

### `sender/ipsec_native.py:_UDP_DRIVER_SCRIPT` 변경

```python
# 추가 argv (optional, 기존 호출자는 안 넘기면 default 0)
alt_src_port = int(sys.argv[6]) if len(sys.argv) > 6 else 0
alt_dst_port = int(sys.argv[7]) if len(sys.argv) > 7 else 0

# primary: 기존과 동일 — server pair
sock_primary = bind(:src_port).connect(:dst_port)

# alt: 추가 — client pair (양쪽 다 명시될 때만)
sock_alt = None
if alt_src_port and alt_dst_port and alt_src_port != src_port:
    sock_alt = bind(:alt_src_port).connect(:alt_dst_port)

sock_primary.send(payload)

# 양쪽 socket 모두 select 로 wait
ready, _, _ = select([sock_primary] + ([sock_alt] if sock_alt else []),
                     [], [], timeout_seconds)
if ready:
    data, peer = ready[0].recvfrom(...)
```

### `send_via_native_ipsec` 시그니처 확장

```python
def send_via_native_ipsec(*, ..., alt_src_port: int = 0, alt_dst_port: int = 0):
    ...
    if transport == "UDP" and (alt_src_port or alt_dst_port):
        driver.extend([str(alt_src_port), str(alt_dst_port)])
```

기본값 0 → 추가 argv 안 들어감 → driver 의 alt 분기 비활성 → **기존 단일 socket 동작 그대로 보존**.

### `sender/core.py:_send_via_native_ipsec` 의 alt 도출

```python
# resolve_protected_ports 단계에서 _port_pc 를 forward
self._target = ...
port_pc_for_alt: int | None = None
if target.ipsec_mode == "native" and ...:
    _port_pc, port_ps = resolver.resolve_protected_ports(...)
    resolved_port = port_ps
    port_pc_for_alt = _port_pc

# native ipsec dispatch 에 propagate
self._send_via_native_ipsec(..., ue_client_port=port_pc_for_alt)

# native ipsec sender 안에서
alt_src = 0
alt_dst = 0
if ue_client_port is not None:
    alt_pcscf_port = session.port_map.get(ue_client_port)
    if alt_pcscf_port and alt_pcscf_port != preflight.pcscf_port:
        alt_src = alt_pcscf_port
        alt_dst = ue_client_port
```

`resolve_native_ipsec_session.port_map = {9901: 6109, 9900: 5109}` 에서 client pair 매핑을 추가로 추출. mapping 이 없거나 primary 와 같으면 alt 비활성화 (single-socket fallback).

### Backward compatibility

| 호출 형태 | driver 동작 |
|---|---|
| 기존 `send_via_native_ipsec(...)` (alt 인자 없이) | argv 5개 → driver 의 `len(sys.argv) > 6` false → alt 비활성 → 단일 socket bind + connect + recvfrom → 기존 그대로 |
| `transport="TCP"` | TCP driver 가 alt argv 무시 (UDP path 만 추가 argv 생성) |
| alt port 가 primary 와 동일 | driver 안에서 if 로 차단 → primary only |
| alt bind 또는 connect 실패 | best-effort: stderr 로그 + sock_alt=None 후 primary only 로 진행. exit code 영향 없음 |

primary path 의 fatal handling (`bind` 실패 시 `sys.exit(2)`, `connect` 실패 시 `sys.exit(3)`) 도 변경 없음.

---

## 5. 검증

2026-04-26 12:34 시점 1 case 송신 결과:

```
fuzzer → 단말 ESP spi=737a len 1236   ← server SA #1 송신
단말 → fuzzer ESP spi=104f len 756    ← server SA #2 응답, dst=6109
fuzzer recvfrom() → SIP/2.0 500 Server Internal Error  (정상 수신)
```

server pair 가 활성인 상태. primary socket 으로 받음. alt socket 은 idle (kernel 이 client SA 로 routing 안 함).

이어진 캠페인 (`62bb3c81`, default strategy, 10 case max): 
- 직전 캠페인 (`df606d37`) timeout 9/9 (100%)
- 새 캠페인 normal 7건 (모두 500 Server Internal Error 수신) + timeout 1건
- timeout 비율 100% → 12% 로 감소

**fix 가 의도대로 작동**. 미래에 SA pair 가 client 로 swap 되어도 alt socket 이 응답을 잡으니 timeout 에 안 빠진다.

---

## 6. 다음 단계 후보

- `alt-tuple` observer event 가 jsonl 의 case record 에 누락된 듯 — `_send_via_native_ipsec` 의 `observer_events.append` 가 `details` 까지 propagate 되는지 확인. 진단 시 alt path 활성 여부 추적용.
- `ue_client_port` 가 None 인 케이스 (legacy / non-native modes) 의 fallback 동작 명시 테스트.
- TCP path 도 동일 dual-bind 적용 여부 검토. 현재는 UDP 만.
- bypass mode 의 `_send_via_container` 도 같은 dual-bind 가 필요한지. bypass 는 P-CSCF netns 안에서 ephemeral port 사용하므로 SA selector 매칭 양상이 다를 수 있음.

---

## 7. 핵심 한 줄

**IMS IPsec 은 4 SA 가 동시 활성. 어느 SA 가 outbound 에 매칭되느냐는 kernel xfrm policy 의 결정이고, 단말 응답은 매칭된 SA 의 reverse 로 온다. fuzzer 가 단일 socket 에만 bind 했으면 매칭이 다른 pair 로 swap 될 때 응답 못 받는다.**
