# 2026-04-21 — srsENB에서 일부 UE가 간헐적으로 안 붙는 경우 정리

## 문제 맥락

실험실 환경에서 `srsENB + USRP B210 + Open5GS` 조합으로 LTE/IMS 망을 올릴 때,
어떤 단말은 잘 camp/attach/register 되는데 어떤 단말은 유독 eNB에 잘 안 붙는
경우가 있다.

현재 저장소 기준 설정은 다음과 같다.

- [`infrastructure/srsenb/enb.conf`](../../infrastructure/srsenb/enb.conf)
  - `n_prb = 50`
  - `tx_gain = 80`
  - `rx_gain = 40`
  - `device_name = uhd`
  - `device_args = type=b200`
- [`infrastructure/srsenb/rr.conf`](../../infrastructure/srsenb/rr.conf)
  - `dl_earfcn = 1600`
- [`infrastructure/srsenb/sib.conf`](../../infrastructure/srsenb/sib.conf)
  - `sib1.q_rx_lev_min = -65`
  - `sib3.intra_freq_reselection.q_rx_lev_min = -61`

핵심 판단은 다음과 같다.

- 이 현상은 보통 "별도 SDR bandwidth 파라미터를 안 만져서" 생기는 문제라기보다,
  **밴드/주파수 조합, 셀 선택 threshold, gain, RF 안정성, UE별 tolerance 차이** 쪽일 가능성이 더 크다.
- 현재 설정에서 LTE 셀 대역폭 축은 사실상 `n_prb`가 담당한다.
  즉 "대역폭을 바꾸고 싶다"는 말은 대부분 `n_prb`를 바꾸는 뜻에 가깝다.

## 현재 판단

### 1. `n_prb`가 현재 대역폭 역할을 한다

현재 설정의 [`enb.conf`](../../infrastructure/srsenb/enb.conf) 에서
`n_prb = 50` 이므로 LTE 기준으로 10 MHz 셀에 해당한다.

따라서 "srsRAN을 쓸 때 SDR bandwidth를 별도로 꼭 맞춰야 하나?"라는 질문에는
현재 저장소 경로 기준으로는 **대체로 아니다**라고 본다.

먼저 손댈 값은 일반적으로 아래 순서다.

1. `sib.conf`의 threshold (`q_rx_lev_min`)
2. `tx_gain` / `rx_gain`
3. `dl_earfcn`
4. 마지막에 `n_prb`

### 2. 일부 단말만 안 붙으면 대역폭보다 호환성/RF 쪽이 더 의심된다

같은 eNB에서 어떤 UE는 잘 붙고 어떤 UE만 자주 실패한다면,
보통 아래 원인이 더 유력하다.

- `EARFCN`/Band 조합에 대한 단말별 민감도 차이
- 셀 선택 threshold가 빡빡해서 약한 수신 단말이 camp를 못함
- gain 고정값이 특정 단말에는 과하거나 부족함
- B210/USB/UHD 상태가 불안정해서 RACH/RRC 타이밍이 흔들림

즉, **모든 단말이 다 같이 안 붙는 문제**가 아니라
**일부 단말만 간헐적으로 안 붙는 문제**라면 `n_prb` 하나만 바꾸는 접근은
우선순위가 낮다.

## 원인 후보 우선순위

### 1. `EARFCN` / Band 호환성

현재 [`rr.conf`](../../infrastructure/srsenb/rr.conf) 의 `dl_earfcn = 1600` 은
Band 3 쪽으로 보는 것이 자연스럽다.

일부 UE는:

- 특정 Band를 더 선호하거나
- 시험망 셀 탐색에서 특정 주파수 조합에 덜 우호적이거나
- 동일 Band라도 셀 탐색/재선택에서 더 까다롭게 동작할 수 있다.

**증상**:

- 셀을 잘 못 찾음
- LTE 표시가 불안정함
- 어떤 단말은 붙고 어떤 단말은 거의 못 붙음

### 2. 셀 선택 threshold가 너무 높음

현재 [`sib.conf`](../../infrastructure/srsenb/sib.conf) 의
`q_rx_lev_min = -65`, `-61` 은 꽤 강한 신호를 요구하는 편이다.

이 값이 높으면:

- 단말이 셀을 보더라도 camp를 포기할 수 있고
- 위치나 안테나 방향에 따라 attach 성공률이 크게 흔들릴 수 있다.

특히 수신이 약한 단말, RF front-end가 예민한 단말에서 차이가 크게 난다.

### 3. `tx_gain` / `rx_gain` 고정값 부적합

현재 [`enb.conf`](../../infrastructure/srsenb/enb.conf) 의
`tx_gain = 80`, `rx_gain = 40` 은 모든 단말에 최적이라고 보기 어렵다.

가능한 문제:

- downlink가 너무 세서 특정 단말에서 왜곡 또는 불안정
- uplink가 약해서 UE의 RACH/RRC 절차를 eNB가 안정적으로 못 받음
- 주변 간섭이나 안테나 배치에 따라 단말별 차이가 더 커짐

### 4. B210 / UHD / 호스트 안정성

`srsENB + B210` 경로는 상용 eNB보다 단말 tolerance 차이를 더 잘 드러낸다.

가능한 현상:

- UHD underrun/overrun
- USB 대역/전원 이슈
- 클럭 오차 또는 동기 안정성 부족
- 호스트 부하에 따른 RACH/RRC 타이밍 흔들림

이 경우 어떤 UE는 그냥 붙지만, 더 보수적인 UE는 camp/attach에 실패할 수 있다.

### 5. RF가 아니라 EPC/가입자 문제

이건 "셀은 보이고 RRC도 일부 진행되는 것 같은데 attach만 실패"일 때 의심한다.

가능한 축:

- SIM/HSS/AUC 정보 mismatch
- PLMN/TAC 관련 단말 정책
- MME/HSS 상태 문제
- attach 이후 IMS registration 전제 누락

이 경우는 RF 대역폭 조정보다 EPC/auth 쪽 확인이 우선이다.

## 증상별 분류

### A. 아예 셀 camp가 잘 안 됨

이 경우는 보통 RF/셀 설정 문제 쪽이다.

우선 의심할 것:

- `dl_earfcn`
- `q_rx_lev_min`
- `tx_gain`, `rx_gain`
- B210/UHD 안정성

### B. 셀은 보이는데 attach가 안 됨

이 경우는 EPC/auth 쪽 가능성이 높다.

우선 의심할 것:

- MME/HSS/AUC subscriber 상태
- PLMN/TAC mismatch
- 단말이 test PLMN을 어떻게 다루는지
- attach reject / auth reject 로그

### C. attach는 되는데 IMS registration이 불안정함

이 경우는 eNB보다는 IMS/HSS/P-CSCF/IPsec 쪽이다.

우선 의심할 것:

- PyHSS / Open5GS provisioning
- P-CSCF / S-CSCF 상태
- xfrm SA 생성 여부
- 단말의 VoLTE/IMS registration 상태

## 1차 점검 순서

일부 단말이 `srsENB`에 잘 안 붙는다고 느껴질 때는 아래 순서가 가장 현실적이다.

1. **먼저 RF vs EPC를 구분한다**
   - 셀을 못 보는가?
   - 셀은 보이지만 attach가 실패하는가?
   - attach는 되지만 IMS registration이 안 되는가?

2. **RF 문제 같으면 `n_prb`보다 threshold/gain부터 본다**
   - `sib.conf`의 `q_rx_lev_min`
   - `enb.conf`의 `tx_gain`, `rx_gain`

3. **그 다음 `EARFCN`을 의심한다**
   - 현재 단말이 지금 주파수 조합에 잘 붙는지
   - 특정 단말에서만 유독 취약한지

4. **그 이후에만 `n_prb`를 만진다**
   - 셀 플랜 자체가 10 MHz가 아닌 경우
   - 호스트/B210이 현재 폭에서 불안정한 경우
   - 실험 목표상 5/10/20 MHz를 맞춰야 하는 경우

## `n_prb`를 바꿔볼 만한 경우

아래 경우에는 `n_prb` 조정이 의미가 있을 수 있다.

- 현재 연구실 셀이 실제로 10 MHz가 아니라 5 MHz 또는 20 MHz 기준이어야 할 때
- `srsENB` 로그에서 샘플 처리/실시간성 문제가 의심될 때
- 특정 셀 폭에서만 UE가 안정적으로 camp하는 것이 관찰될 때

일반적으로는:

- `n_prb = 25` → 5 MHz
- `n_prb = 50` → 10 MHz
- `n_prb = 100` → 20 MHz

하지만 현재 저장소/설정만 놓고 보면,
**일부 UE의 간헐 attach 실패를 설명하는 1차 원인으로 `n_prb`를 바로 지목하긴 어렵다.**

## 현재 결론

현재 repo의 `srsENB` 설정 기준으로,
"srsRAN을 쓸 때 SDR bandwidth도 꼭 따로 조정해야 하나?" 보다는
아래 질문이 더 정확하다.

- 지금 단말이 현재 `EARFCN`/Band 조합을 잘 잡는가?
- `q_rx_lev_min`이 너무 빡빡하지 않은가?
- `tx_gain`/`rx_gain`이 특정 단말에 과하거나 부족하지 않은가?
- B210/UHD/호스트 상태가 충분히 안정적인가?

즉, **일부 단말만 안 붙는 현상은 대역폭 하나의 문제라기보다
RF 호환성/셀 선택/RACH 안정성 문제일 가능성이 높다.**
