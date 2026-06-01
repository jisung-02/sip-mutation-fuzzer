#!/usr/bin/env bash
#
# One-shot Ubuntu bootstrap for VolteMutationFuzzer real-device workflows.
#
# This script is intentionally safe by default:
# - installs host packages and Python project dependencies
# - enables docker/usbmuxd when systemd is available
# - does not mutate kernel/sysctl/SDR settings unless --with-host-setup is used
# - does not build IMS Docker images unless --build-images is used
#
# What this installs and why:
# - software-properties-common, ca-certificates, curl, gnupg, sudo, passwd:
#   basic Ubuntu repository, HTTPS, installer, privilege, and user/group
#   plumbing used by apt, uv, and post-install docker/plugdev membership.
# - git:
#   repository checkout/update support on a fresh machine.
# - lsb-release, python3, python3-dev, python3-pip, python3-venv:
#   base Python tooling and headers. The project itself is managed by uv, but
#   these keep Ubuntu-side scripts and package builds predictable.
# - iproute2, iptables, kmod, procps, udev, usbutils, net-tools, iputils-ping,
#   netplan.io:
#   host networking/kernel utilities used for UE routes, xfrm inspection,
#   Docker bridge checks, kernel modules, USB device rules, persistent route
#   examples, and diagnostics.
# - linux-modules-extra-$(uname -r), when available:
#   extra kernel modules such as SCTP on minimal Ubuntu installations. The
#   package is optional because cloud/custom kernels may not publish a matching
#   Ubuntu package.
# - docker.io plus docker-compose-v2/docker-compose-plugin:
#   local Open5GS/Kamailio/IMS core, P-CSCF/S-CSCF lookups, container logs,
#   and optional EPC/IMS image build/run tasks. The script verifies that the
#   required `docker compose` subcommand exists after installation.
# - tcpdump, tshark:
#   packet capture and pcap-to-text export for campaign evidence.
# - jq:
#   command-line JSON filtering used by operational/report-analysis snippets.
# - adb or android-tools-adb:
#   Android UE detection, logcat streaming, dumpsys snapshots, and crash
#   evidence collection.
# - libimobiledevice-utils, ideviceinstaller, usbmuxd, libplist-utils,
#   optional libimobiledevice6:
#   iPhone UDID/device-info lookup, syslog streaming, crash report pulls, and
#   USB pairing/transport support for the --ios campaign path.
# - uv:
#   Python version management, virtualenv creation, project dependency sync,
#   and command execution via uv run.
# - Python from .python-version and uv sync --dev:
#   installs the interpreter expected by this checkout and the runtime/dev
#   dependencies, including fuzzer CLI, tests, lint/type tools, and poe tasks.
# - setup_host.sh --all, only with --with-host-setup:
#   writes sysctl/module/udev/realtime/CPU-governor host settings needed by
#   real IMS/SDR hosts. It is opt-in because it changes system configuration.
# - uv run poe epc-build, only with --build-images:
#   builds local Open5GS/Kamailio/IMS Docker images. It is opt-in because it is
#   slow and depends on network access to upstream source/package repositories.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RUN_HOST_SETUP=0
BUILD_IMAGES=0
RUN_UV_SYNC=1
INSTALL_UV_PYTHON=1
PYTHON_VERSION=""

log() {
  printf '[vmf bootstrap] %s\n' "$*"
}

warn() {
  printf '[vmf bootstrap] warning: %s\n' "$*" >&2
}

die() {
  printf '[vmf bootstrap] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/bootstrap_ubuntu.sh [options]

Install VolteMutationFuzzer prerequisites on a fresh Ubuntu host.

Options:
  --project-dir DIR       Project directory to bootstrap. Default: repo root.
  --python VERSION        Python version for uv to install. Default: .python-version or 3.14.
  --with-host-setup       Also run sudo ./setup_host.sh --all.
  --build-images          Also run uv run poe epc-build after uv sync --dev.
  --no-uv-python          Skip uv python install.
  --no-uv-sync            Skip uv sync --dev.
  -h, --help              Show this help.

Default installs:
  apt packages: git/curl/python, Docker, docker compose, tcpdump/tshark,
                jq, adb, libimobiledevice/usbmuxd, network/kernel utilities
  user tools:   uv, Python from .python-version, project dev dependencies

Post-install notes:
  - Log out and back in after docker/plugdev group changes.
  - Campaign pcap capture uses sudo tcpdump. Run sudo -v before unattended
    campaigns, or add a narrow sudoers rule for /usr/bin/tcpdump.
  - Use --with-host-setup only on the actual IMS/SDR host; it writes sysctl,
    module-load, udev, realtime, and CPU-governor settings.
  - Use --build-images only when you want the local Open5GS/Kamailio IMS
    Docker images built during bootstrap.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir)
      [[ $# -ge 2 ]] || die "--project-dir requires a value"
      PROJECT_DIR="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || die "--python requires a value"
      PYTHON_VERSION="$2"
      shift 2
      ;;
    --with-host-setup)
      RUN_HOST_SETUP=1
      shift
      ;;
    --build-images)
      BUILD_IMAGES=1
      shift
      ;;
    --no-uv-python)
      INSTALL_UV_PYTHON=0
      shift
      ;;
    --no-uv-sync)
      RUN_UV_SYNC=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

PROJECT_DIR="$(cd "${PROJECT_DIR}" && pwd)"

if [[ -z "${PYTHON_VERSION}" ]]; then
  if [[ -f "${PROJECT_DIR}/.python-version" ]]; then
    PYTHON_VERSION="$(tr -d '[:space:]' < "${PROJECT_DIR}/.python-version")"
  fi
  PYTHON_VERSION="${PYTHON_VERSION:-3.14}"
fi

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  TARGET_USER="${SUDO_USER}"
else
  TARGET_USER="${USER:-root}"
fi

TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6 || true)"
TARGET_HOME="${TARGET_HOME:-${HOME}}"
UV_BIN="${TARGET_HOME}/.local/bin/uv"

if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
  die "sudo is required when not running as root; rerun as root or install sudo first"
fi

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

run_as_target_user() {
  if [[ "${TARGET_USER}" == "root" ]]; then
    HOME="${TARGET_HOME}" "$@"
  else
    ${SUDO} -H -u "${TARGET_USER}" "$@"
  fi
}

run_as_target_user_shell() {
  local command="$1"
  if [[ "${TARGET_USER}" == "root" ]]; then
    HOME="${TARGET_HOME}" bash -lc "${command}"
  else
    ${SUDO} -H -u "${TARGET_USER}" bash -lc "${command}"
  fi
}

require_ubuntu() {
  [[ -r /etc/os-release ]] || die "/etc/os-release not found"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "unsupported OS: ${ID:-unknown}; Ubuntu is required"
  log "detected Ubuntu ${VERSION_ID:-unknown}"
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get install -y "$@"
}

apt_has_package() {
  apt-cache show "$1" >/dev/null 2>&1
}

install_apt_packages() {
  log "updating apt package index"
  ${SUDO} apt-get update

  log "installing base package helpers"
  apt_install software-properties-common ca-certificates curl gnupg sudo passwd
  if command -v add-apt-repository >/dev/null 2>&1; then
    ${SUDO} add-apt-repository -y universe >/dev/null 2>&1 || true
    ${SUDO} apt-get update
  fi

  log "preseeding tshark to avoid interactive package prompts"
  printf 'wireshark-common wireshark-common/install-setuid boolean false\n' \
    | ${SUDO} debconf-set-selections || true

  log "installing core host packages"
  apt_install \
    git \
    lsb-release \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    iproute2 \
    iptables \
    kmod \
    procps \
    udev \
    usbutils \
    net-tools \
    iputils-ping \
    netplan.io \
    jq \
    docker.io \
    tcpdump \
    tshark \
    libimobiledevice-utils \
    ideviceinstaller \
    usbmuxd \
    libplist-utils

  local kernel_modules_extra
  kernel_modules_extra="linux-modules-extra-$(uname -r)"
  if apt_has_package "${kernel_modules_extra}"; then
    log "installing optional ${kernel_modules_extra} for kernel module coverage"
    apt_install "${kernel_modules_extra}"
  else
    warn "optional ${kernel_modules_extra} not found; continuing"
  fi

  if apt_has_package libimobiledevice6; then
    apt_install libimobiledevice6
  fi

  if apt_has_package adb; then
    apt_install adb
  else
    apt_install android-tools-adb
  fi

  if apt_has_package docker-compose-v2; then
    apt_install docker-compose-v2
  elif apt_has_package docker-compose-plugin; then
    apt_install docker-compose-plugin
  elif apt_has_package docker-compose; then
    warn "installing legacy docker-compose package; docker compose v2 will be verified next"
    apt_install docker-compose
  else
    die "no docker compose package found; install Docker Compose v2 plugin and retry"
  fi
}

verify_required_commands() {
  log "verifying required host commands"

  local missing=0
  local cmd
  for cmd in docker tcpdump tshark jq adb idevice_id; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      warn "required command not found after install: ${cmd}"
      missing=1
    fi
  done

  if ! docker compose version >/dev/null 2>&1; then
    warn "docker compose subcommand is not available after package install"
    warn "install docker-compose-v2 or docker-compose-plugin from Ubuntu/Docker repositories"
    missing=1
  fi

  [[ "${missing}" -eq 0 ]] || die "one or more required host commands are unavailable"
}

enable_services() {
  if command -v systemctl >/dev/null 2>&1; then
    log "enabling docker and usbmuxd services"
    ${SUDO} systemctl enable --now docker || warn "could not enable docker"
    ${SUDO} systemctl enable --now usbmuxd || warn "could not enable usbmuxd"
  else
    warn "systemctl not found; start docker/usbmuxd manually if needed"
  fi
}

configure_user_groups() {
  log "adding ${TARGET_USER} to docker/plugdev groups when present"
  if getent group docker >/dev/null 2>&1; then
    ${SUDO} usermod -aG docker "${TARGET_USER}" || warn "could not add ${TARGET_USER} to docker"
  fi
  if getent group plugdev >/dev/null 2>&1; then
    ${SUDO} usermod -aG plugdev "${TARGET_USER}" || warn "could not add ${TARGET_USER} to plugdev"
  fi
}

install_uv() {
  if run_as_target_user_shell "command -v uv >/dev/null 2>&1"; then
    UV_BIN="$(run_as_target_user_shell 'command -v uv')"
    log "uv already installed: ${UV_BIN}"
    return
  fi

  log "installing uv for ${TARGET_USER}"
  run_as_target_user_shell 'curl -LsSf https://astral.sh/uv/install.sh | sh'
  [[ -x "${UV_BIN}" ]] || die "uv installer finished but ${UV_BIN} was not found"
}

run_uv_setup() {
  local uv_cmd="${UV_BIN}"
  if [[ ! -x "${uv_cmd}" ]]; then
    uv_cmd="$(run_as_target_user_shell 'command -v uv')"
  fi

  if [[ "${INSTALL_UV_PYTHON}" -eq 1 ]]; then
    log "installing Python ${PYTHON_VERSION} via uv"
    run_as_target_user "${uv_cmd}" python install "${PYTHON_VERSION}"
  fi

  if [[ "${RUN_UV_SYNC}" -eq 1 ]]; then
    log "syncing project dependencies with uv sync --dev"
    run_as_target_user_shell "cd '${PROJECT_DIR}' && '${uv_cmd}' sync --dev"
  fi
}

run_optional_host_setup() {
  if [[ "${RUN_HOST_SETUP}" -ne 1 ]]; then
    log "skipping setup_host.sh --all; pass --with-host-setup to run it"
    return
  fi

  [[ -x "${PROJECT_DIR}/setup_host.sh" || -f "${PROJECT_DIR}/setup_host.sh" ]] \
    || die "setup_host.sh not found in ${PROJECT_DIR}"
  log "running sudo ./setup_host.sh --all"
  (cd "${PROJECT_DIR}" && ${SUDO} ./setup_host.sh --all)
}

run_optional_image_build() {
  if [[ "${BUILD_IMAGES}" -ne 1 ]]; then
    log "skipping IMS Docker image build; pass --build-images to run uv run poe epc-build"
    return
  fi

  log "building IMS Docker images with uv run poe epc-build"
  run_as_target_user_shell "cd '${PROJECT_DIR}' && '${UV_BIN}' run poe epc-build"
}

print_summary() {
  cat <<EOF
[vmf bootstrap] complete.

Next steps:
  1. Log out and back in so docker/plugdev group membership applies.
  2. Verify tools:
       docker --version
       docker compose version
       tcpdump --version
       tshark --version
       jq --version
       adb version
       idevice_id --version
       ${UV_BIN} --version
  3. From the project:
       cd ${PROJECT_DIR}
       ${UV_BIN} run fuzzer --help
  4. For unattended --pcap campaigns:
       sudo -v
     or add a narrow sudoers rule such as:
       <user> ALL=(ALL) NOPASSWD: /usr/bin/tcpdump

Optional real-UE setup:
  - Host kernel/network/SDR setup: bash scripts/bootstrap_ubuntu.sh --with-host-setup
  - IMS image build:              bash scripts/bootstrap_ubuntu.sh --build-images
EOF
}

main() {
  require_ubuntu
  install_apt_packages
  verify_required_commands
  enable_services
  configure_user_groups
  install_uv
  run_uv_setup
  run_optional_host_setup
  run_optional_image_build
  print_summary
}

main "$@"
