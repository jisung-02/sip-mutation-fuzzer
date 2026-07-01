#!/bin/bash
#
# Install Ubuntu system dependencies used by VolteMutationFuzzer.
# This task intentionally excludes softphone/baresip installation.
#

set -euo pipefail

PACKAGES=(
  docker.io
  docker-compose
  tcpdump
  wireshark-cli
  adb
  libimobiledevice6
  libimobiledevice-utils
  ideviceinstaller
  usbmuxd
  libplist-utils
)

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

if [[ ! -r /etc/os-release ]]; then
  echo "[vmf install] unsupported environment: /etc/os-release not found" >&2
  exit 2
fi

# shellcheck disable=SC1091
. /etc/os-release

if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "[vmf install] unsupported OS: ${ID:-unknown}. This task supports Ubuntu only." >&2
  exit 2
fi

echo "[vmf install] updating apt package index..."
$SUDO apt-get update

echo "[vmf install] installing system packages (softphone excluded)..."
$SUDO apt-get install -y "${PACKAGES[@]}"

echo "[vmf install] enabling usbmuxd for iPhone collection..."
$SUDO systemctl enable --now usbmuxd

cat <<'EOF'
[vmf install] done.
- Installed: docker, tcpdump/tshark, adb, libimobiledevice/usbmuxd
- Excluded intentionally: baresip (softphone)
- Next optional steps:
  1. poe setup-host
  2. uv sync --dev
EOF
