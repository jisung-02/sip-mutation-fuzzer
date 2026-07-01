# Server Setup

이 문서는 현재 IMS testbed에서 VolteMutationFuzzer를 돌리기 위한 서버 쪽 확인 절차만 담는다. 특정 UE IP를 고정하지 않는다.

## Requirements

- Ubuntu host
- Docker-based IMS stack
- `pcscf`, `scscf`, Open5GS components running
- UE가 test PLMN에 attach/register 가능한 RF 환경
- Python 3.12+ and `uv`

Project setup:

```bash
uv sync
poe install
```

## Core Containers

```bash
docker ps
docker logs pcscf --since 2m
docker exec pcscf kamctl ul show
docker exec pcscf ip xfrm state
```

## Network Checks

P-CSCF IP:

```bash
export VMF_REAL_UE_PCSCF_IP=172.22.0.21
```

UE route:

```bash
ip route | grep 10.20.20
ip link show br-volte
```

If routing is missing:

```bash
uv run fuzzer infra setup-route \
  --ims-subnet 10.20.20.0/24 \
  --upf-ip 172.22.0.8
```

## Resolver Inputs

The fuzzer resolves UE state from:

1. `kamctl ul show`
2. P-CSCF logs
3. `ip xfrm state`
4. explicit `VMF_MSISDN_TO_IP_<MSISDN>` override

There is no hardcoded MSISDN to IP fallback. This is intentional. Stale device slots were causing silent misroutes.

## Protected Ports

Do not assume adjacent `port_pc` / `port_ps`. Native IPsec resolution must use
live `Security-Client` and xfrm `dport` mapping.

## Baseline Command

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --ipsec-mode native \
  --max-cases 1
```
