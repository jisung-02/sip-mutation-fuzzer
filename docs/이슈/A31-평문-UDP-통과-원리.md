# A31이 평문 UDP를 통과시키는 이유 — XFRM 정책 분석

> **질문**: 3GPP TS 33.203이 UE↔P-CSCF 사이 SIP 트래픽을 IPsec ESP로 보호하라고
> 규정하는데, 왜 A31은 P-CSCF IP(172.22.0.21)에서 오는 **평문 UDP**를 drop하지
> 않고 수락하는가?
>
> 이 문서는 Linux XFRM 동작 원리를 근거로 가장 그럴듯한 답을 낸다. A31 내부
> 정책을 직접 볼 수 없으므로 100% 확정은 불가능하지만, pcscf 컨테이너의
> mirror policy로부터 거의 확실하게 역산할 수 있다.

---

## 1. Linux XFRM은 "whitelist 기반 enforcement"다

XFRM inbound 정책의 핵심 룰:

> **정책 selector에 매치되는 패킷만** IPsec 요구를 강제한다.
> 어떤 정책에도 매치 안 되는 패킷은 **그냥 통과시킨다**.

즉, xfrm은 "이 트래픽은 반드시 ESP여야 한다"를 **화이트리스트**로 선언하는
것이지, "ESP 아닌 건 전부 drop"하는 블랙리스트가 아니다.

이 전제 하나가 전체 답의 출발점이다.

---

## 2. A31의 inbound xfrm policy는 어떻게 생겼나

A31 내부를 직접 볼 수는 없지만, Kamailio P-CSCF가 REGISTER 중에 UE 쪽에
요청한 정책을 역산할 수 있다. pcscf 컨테이너의 xfrm policy (outbound)에서:

```
src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8101  dir out
src 172.22.0.21/32 dst 10.20.20.8/32 sport 6103 dport 8100  dir out
src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8100  dir out
src 172.22.0.21/32 dst 10.20.20.8/32 sport 6103 dport 8101  dir out
```

A31 쪽 **inbound 정책은 이걸 거울처럼 복사**한 형태일 것이다 (IMS AKA negotiate
후 UE 커널에 설치됨):

```
src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8101  dir in  proto esp
src 172.22.0.21/32 dst 10.20.20.8/32 sport 6103 dport 8100  dir in  proto esp
src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8100  dir in  proto esp
src 172.22.0.21/32 dst 10.20.20.8/32 sport 6103 dport 8101  dir in  proto esp
```

**모든 정책이 `sport=5103 또는 6103`이다.** Kamailio가 자기 protected client
port(5103)와 protected server port(6103)로 나가는 것만 IPsec으로 보호받길
원했기 때문.

---

## 3. 우리가 보내는 패킷은?

```
src 172.22.0.21:15100  dst 10.20.20.8:8100   (평문 UDP)
                 ^^^^^
                 sport = 15100
```

| 필드 | 값 |
|---|---|
| source IP | 172.22.0.21 (P-CSCF) |
| source port | **15100** (fuzzer가 `--mt-local-port`로 지정한 포트) |
| dest IP | 10.20.20.8 (A31 UE IP) |
| dest port | 8100 (A31 port_pc) |
| protocol | 평문 UDP (ESP 아님) |

- A31 inbound 정책들은 전부 `sport 5103` 또는 `sport 6103`을 요구
- 우리 패킷은 `sport 15100`
- **매치되는 정책이 하나도 없음**
- → xfrm은 이 패킷에 IPsec 요구를 적용하지 않음
- → 평문 그대로 application 레이어로 올라감

---

## 4. Application 레이어는 평문 UDP를 어떻게 수락하는가

XFRM을 통과한 뒤에 하나의 필터가 더 걸린다. A31의 IMS 앱 (Samsung dialer /
IMS stack)은:

1. UDP 소켓으로 **port_pc(8100)**에서 SIP 메시지 수신 대기
2. 수신한 패킷에 대해 **source IP 화이트리스트 체크**
   - 등록 시 사용한 P-CSCF IP(172.22.0.21)인가? → 통과
   - 그 외 → 조용히 drop
3. Source port는 체크하지 **않음** (SIP 표준상 임의 포트 OK)
4. SIP 파싱 → dialog 상태 확인 → INVITE면 수신 UI 띄우고 벨 울림

그래서 우리 패킷이:

- `src=172.22.0.21` 통과 ✓
- `dport=8100`(port_pc)에서 수신 중 ✓
- `sport=15100` 무시 ✓
- SIP 내용 3GPP 완전 포맷 ✓

모든 체크 통과 → **벨 울림.**

---

## 5. 만약 sport=5103으로 보냈다면?

그림이 완전히 달라진다:

- A31의 inbound xfrm 정책 `sport 5103 dport 8101 dir in proto esp`에 **매치**
- 정책이 요구: "이 selector의 패킷은 ESP여야 함"
- 우리 패킷은 평문
- → **커널이 drop** (level required 가정 시)

즉 **우리가 high port(15100)를 써서 정책을 회피하는 것**이 핵심이다. Kamailio가
예약한 포트를 건드리지 않으니 xfrm이 "이건 내 관심사 아님" 하고 통과시키는 것.

이 때문에 `--mt-local-port` 기본값을 **Kamailio 점유 포트(5060, 5100–5103,
6101–6103)와 겹치지 않는 high port**(15100)로 잡아놓았다. 다른 값을 쓸 거면
반드시 이 범위를 피해야 한다.

---

## 6. 3GPP 표준은 뭐라고 하나

**3GPP TS 33.203** (IMS security):

- REGISTER 후 UE와 P-CSCF 사이 **모든 SIP 트래픽**을 IPsec ESP로 보호해야 한다고
  규정
- "UE and P-CSCF shall apply integrity and confidentiality protection"
  (3GPP TS 33.203 §7.2)

근데 **실제 구현은 selector를 좁게 건다**:

- Kamailio: IMS AKA negotiate 끝나면 `ipsec_create` 모듈이 xfrm state/policy를
  설치. 이때 selector는 자기가 내보낼 포트(5103/6103)에만 걸린다.
- UE 측: IKE가 아닌 **SIP 레이어 합의**로 같은 정책을 설치. 당연히 selector도
  같은 범위.

표준의 의도는 "전부 보호"지만, 구현 레벨에서 selector가 좁게 설정되어 있으면
"정책 바깥의 포트"는 enforcement 대상이 아니게 된다.

**이게 표준과 구현의 간극**이고, fuzzer가 파고든 틈이다. 정상 IMS 시그널링은
정의된 포트만 쓰기 때문에 이 틈이 문제가 되지 않지만, 우리는 임의 포트에서
의도적으로 보낸다.

---

## 7. 다른 가능성 — 기각된 시나리오들

### 가능성 A: `level use` vs `level required`

Linux xfrm 정책은 두 가지 enforcement 모드가 있다:

| 모드 | 동작 |
|---|---|
| `level required` | ESP 필수. 매치되는데 ESP 아니면 drop. |
| `level use` | ESP 가능하면 쓰지만 평문도 OK. 매치돼도 drop 안 함. |

만약 삼성이 `level use`를 쓰면, 매칭되는 정책이 있어도 평문이 통과한다.

**하지만 이 시나리오는 가능성이 낮다.** 3GPP IMS는 integrity/confidentiality
둘 다 필수라고 규정하므로, `level use`로 구현하면 표준 위반이다. 삼성이
의도적으로 완화했을 수도 있지만, 더 단순한 설명(selector 미매치)이 있으면
그쪽이 우선한다.

### 가능성 B: 앱 레이어만 존재, 커널 xfrm 미사용

삼성 IMS 스택이 커널 xfrm을 쓰지 않고 userspace에서 자체 IPsec을 구현했다면,
커널 레벨에서는 아예 체크가 없다.

**이 시나리오도 기각된다.** 왜냐하면:

- pcscf 쪽 xfrm state에 A31과의 SA가 실제로 등록되어 있음 (`lastused`가
  갱신됨)
- 정상 IMS REGISTER 흐름에서는 pcscf가 ESP로 송신한 것을 A31이 받고 있다는
  증거
- 즉 A31 커널의 xfrm이 분명히 동작 중

### 결론: **selector 미매치가 가장 그럴듯하다**

pcscf 쪽 정책을 보면 selector가 명확히 좁게 걸려 있는 걸 확인할 수 있다.
A31은 거울 정책일 것이고, 우리 sport=15100은 어느 정책에도 매치 안 된다.
Linux XFRM의 기본 동작은 "매치 안 되는 inbound는 enforcement 없이 통과"이므로,
평문이 그대로 올라간다.

---

## 8. 검증 방법 (hypothetical)

만약 A31을 rooting해서 내부를 볼 수 있다면 이렇게 검증할 수 있다:

```bash
# A31 shell (root):
ip xfrm policy | grep -A2 'dir in'
```

예상 결과:

```
src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8101
    dir in priority 2080
    tmpl src 172.22.0.21 dst 10.20.20.8 proto esp reqid <N> mode transport
```

- `sport 5103`, `sport 6103`만 존재 → selector 미매치 가설 확정
- 만약 `sport any` 또는 `sport 0-65535` 같은 wildcard가 있다면 → 이 문서의
  설명이 틀렸다는 뜻

실제 rooting 하지 않더라도, **임의 sport(5103 외)에서 보낸 평문 UDP가 전달되는
것**을 관찰한 사실 자체가 "selector 기반 enforcement"를 강하게 뒷받침한다.

---

## 9. 한 줄 요약

**A31의 inbound xfrm 정책은 Kamailio가 예약한 포트 pair(5103/6103 ↔
8100/8101)만 ESP를 요구한다. 우리 패킷은 sport=15100이라 정책에 매치 안 되고,
Linux XFRM은 매치 안 되는 inbound에 대해 enforcement를 적용하지 않으므로 평문
통과. 그 다음은 앱 레이어의 source-IP 화이트리스트만 통과하면 됨.**

---

## 10. 운영상 함의

### Do

- `--mt-local-port`를 **15100 같은 high port**로 지정 (Kamailio 점유 범위 밖)
- Kamailio가 사용 중인 포트는 `docker exec pcscf ss -ulnp`로 사전 확인
- 정상 IMS REGISTER가 동작 중인 상태 유지 (xfrm SA가 살아있어야 함)

### Don't

- sport를 5103, 6103으로 **절대 설정하지 말 것** — xfrm 정책에 매치돼서 drop됨
- 5100–5103, 6101–6103 대역 전체 회피
- "ESP로 보내보면 더 안전하지 않을까?" 같은 시도 하지 않기 — 키가 없어서 어차피
  불가능하고, 평문이 이미 통과하니 불필요

### 이 틈이 막히는 경우

삼성이 펌웨어 업데이트로 inbound 정책을 wildcard(`sport any dport 8100`)로
확장하거나 `level required`를 전체 P-CSCF↔UE 트래픽에 적용하면 이 경로는
막힌다. 그러면 진짜 ESP를 쓰거나 IPsec SA를 횡취해야 한다 (현실적으로 매우
어려움).

---

## 11. 관련 문서

- `docs/이슈/A31-real-ue-direct-INVITE-성공-기록.md` — 5가지 성공 조건 원문
  (조건 4: "Plaintext UDP works")
- `docs/이슈/A31-real-ue-direct-해결-과정.md` — IPsec/ESP/XFRM 이론 설명 +
  삽질 히스토리
- `docs/이슈/A31-real-ue-direct-시스템-요구사항.md` — 시스템 레벨 전제조건
- `memory/project_a31_real_ue_direct_breakthrough.md` — Claude 메모리 (영어)
