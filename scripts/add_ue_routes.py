#!/usr/bin/env python3
"""UE 서브넷 라우트 추가 (10.10.10.0/24, 10.20.20.0/24) via UPF (172.22.0.8)."""

import subprocess
import sys

ROUTES = [
    ("10.10.10.0/24", "172.22.0.8"),
    ("10.20.20.0/24", "172.22.0.8"),
]


def main() -> None:
    # sudo -v로 자격증명 캐시 (한 번만 비번 요청)
    result = subprocess.run(["sudo", "-v"])
    if result.returncode != 0:
        sys.exit(result.returncode)

    for subnet, via in ROUTES:
        subprocess.run(
            ["sudo", "-n", "ip", "route", "replace", subnet, "via", via], check=True
        )

    print("Routes added:")
    subprocess.run(["ip", "route", "show"])


if __name__ == "__main__":
    main()
