#!/usr/bin/env python3
"""
Docker 컨테이너 내부 트래픽 캡처 도구

사용법: poe tcpdump <container> [protocol] [tcpdump-options...]

컨테이너:
  mme, hss, sgwc, sgwu, smf, upf, pcrf
  pcscf, icscf, scscf, pyhss, dns, rtpengine

프로토콜:
  sip       SIP (port 5060)
  diameter  Diameter (port 3868)
  s1ap      S1AP (port 36412)
  gtpc      GTP-C (port 2123)
  gtpu      GTP-U (port 2152)
  dns       DNS (port 53)
  rtp       RTP (ports 49000-50000)
  sctp      SCTP
  all       전체 (기본값)

예시:
  poe tcpdump pcscf sip
  poe tcpdump pcscf sip -A
  poe tcpdump mme s1ap -vv
  poe tcpdump mme all -w /tmp/mme.pcap
"""

import os
import subprocess
import sys

PROTOCOL_FILTERS: dict[str, str] = {
    "sip": "port 5060",
    "diameter": "port 3868",
    "s1ap": "port 36412",
    "gtpc": "port 2123",
    "gtp-c": "port 2123",
    "gtpu": "port 2152",
    "gtp-u": "port 2152",
    "dns": "port 53",
    "rtp": "portrange 49000-50000",
    "sctp": "sctp",
    "all": "",
}

PROTOCOL_LABELS: dict[str, str] = {
    "sip": "SIP",
    "diameter": "Diameter",
    "s1ap": "S1AP",
    "gtpc": "GTP-C",
    "gtp-c": "GTP-C",
    "gtpu": "GTP-U",
    "gtp-u": "GTP-U",
    "dns": "DNS",
    "rtp": "RTP",
    "sctp": "SCTP",
    "all": "All",
}


def get_running_containers() -> list[str]:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().splitlines()


def show_help() -> None:
    print(__doc__)


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        show_help()
        sys.exit(0)

    container = args[0]
    protocol = args[1].lower() if len(args) > 1 else "all"
    extra_opts = args[2:] if len(args) > 2 else []

    # 알 수 없는 프로토콜은 커스텀 필터로 처리
    if protocol in PROTOCOL_FILTERS:
        tcpdump_filter = PROTOCOL_FILTERS[protocol]
        label = PROTOCOL_LABELS[protocol]
    else:
        tcpdump_filter = protocol
        label = f"Custom ({protocol})"
        # protocol이 옵션처럼 보이면 extra_opts에 포함
        if protocol.startswith("-"):
            tcpdump_filter = ""
            label = "All"
            extra_opts = [protocol] + extra_opts

    # 컨테이너 실행 확인
    running = get_running_containers()
    if container not in running:
        print(f"Error: Container '{container}' is not running")
        print()
        print("Running containers:")
        for name in running:
            print(f"  {name}")
        sys.exit(1)

    print(f"Capturing {label} traffic on {container}...")
    print("Press Ctrl+C to stop")
    print()

    cmd = ["docker", "exec", "-it", container, "tcpdump", "-i", "any", "-n"]
    if tcpdump_filter:
        cmd.append(tcpdump_filter)
    cmd.extend(extra_opts)

    try:
        os.execvp("docker", cmd)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
