# iOS Collection Operations

iPhone 대상 퍼징은 `--ios`를 켜서 libimobiledevice 기반 수집을 붙인다. Jailbreak는 전제하지 않는다.

## Host Setup

Ubuntu 기준:

```bash
sudo apt update
sudo apt install -y \
  libimobiledevice6 \
  libimobiledevice-utils \
  ideviceinstaller \
  usbmuxd \
  libplist-utils
sudo systemctl enable --now usbmuxd
```

연결 확인:

```bash
idevice_id -l
ideviceinfo -k ProductType
ideviceinfo -k ProductVersion
```

USB iPhone이 1대만 연결되어 있으면 `--ios-udid`는 생략한다.

## Campaign Usage

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn <MSISDN> \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --ios \
  --max-cases 50
```

## What Gets Collected

Campaign 시작 시:

- iOS device info
- baseline crash report snapshot
- full-period `syslog_full.txt`

Case별:

- `syslog.txt`
- `syslog_commcenter.txt`
- `syslog_springboard.txt`
- `anomalies.json`
- optional diagnostics when `--ios-diagnostics` is set

Crash reports는 per-case로 매번 덤프하지 않는다. `idevicecrashreport`가 전체 device crash store를 다시 덤프하기 때문에, campaign 시작/종료 diff 방식으로 본다.

## Practical Notes

- `idevicesyslog`는 process filter 없이 전체 syslog를 수집한다.
- `CommCenter` / `SpringBoard` 파일은 case snapshot에서 convenience view로 만든다.
- Carrier profile이 없으면 일부 IMS 로그가 `<private>`로 redacted 될 수 있다.
- iPhone에서 IMS PDN이 안 올라오면 VoLTE 토글과 manual PLMN select를 먼저 확인한다.

## iPhone IMS Attach Checklist

1. iPhone에서 이 컴퓨터 신뢰
2. `idevice_id -l`에서 UDID 확인
3. test PLMN에 attach
4. VoLTE enabled
5. P-CSCF logs에서 REGISTER 확인
6. xfrm state에서 protected port pair 확인
7. identity baseline 1 case 실행
