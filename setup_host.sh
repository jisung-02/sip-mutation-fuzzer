#!/bin/bash
#
# VoLTE Fuzzer - Ubuntu Host Setup Script
# Ubuntu 22.04 / 24.04 시스템 레벨 설정 자동화
#
# Usage:
#   sudo ./setup_host.sh [options]
#
# Options:
#   --all         모든 설정 적용
#   --kernel      커널 모듈만 설정
#   --network     네트워크 설정만 적용
#   --sdr         SDR udev rules만 설치
#   --realtime    실시간 스케줄링 권한만 설정
#   --check       현재 시스템 상태 확인
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Root 권한 확인
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
        exit 1
    fi
}

# Ubuntu 버전 확인
check_ubuntu() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            echo -e "${YELLOW}Warning: This script is designed for Ubuntu. Detected: $ID${NC}"
        else
            echo -e "${GREEN}Detected: Ubuntu $VERSION_ID${NC}"
        fi
    fi
}

print_header() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}VoLTE Fuzzer - Host Setup${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# 1. 커널 모듈 설정
setup_kernel_modules() {
    echo -e "${YELLOW}[1/5] Setting up kernel modules...${NC}"

    # SCTP 모듈 (S1AP용)
    if lsmod | grep -q "^sctp"; then
        echo -e "  ${GREEN}✓${NC} sctp module already loaded"
    else
        echo -e "  Loading sctp module..."
        modprobe sctp || echo -e "  ${YELLOW}⚠ Failed to load sctp (may not be available)${NC}"
    fi

    # RTPEngine 커널 모듈
    if lsmod | grep -q "xt_RTPENGINE"; then
        echo -e "  ${GREEN}✓${NC} xt_RTPENGINE module already loaded"
    else
        echo -e "  Loading xt_RTPENGINE module..."
        modprobe xt_RTPENGINE 2>/dev/null || echo -e "  ${YELLOW}⚠ xt_RTPENGINE not available (will use userspace)${NC}"
    fi

    # 부팅 시 자동 로드 설정
    cat > /etc/modules-load.d/volte-fuzzer.conf << 'EOF'
# VoLTE Fuzzer kernel modules
sctp
xt_RTPENGINE
EOF
    echo -e "  ${GREEN}✓${NC} Created /etc/modules-load.d/volte-fuzzer.conf"
}

# 2. 네트워크 sysctl 설정
setup_network() {
    echo -e "${YELLOW}[2/5] Configuring network parameters...${NC}"

    cat > /etc/sysctl.d/99-volte-fuzzer.conf << 'EOF'
# VoLTE Fuzzer network settings

# IP Forwarding (required for packet routing)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Disable Reverse Path Filtering (required for IMS traffic)
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# Allow binding to non-local addresses (for P-CSCF)
net.ipv4.ip_nonlocal_bind = 1
net.ipv6.ip_nonlocal_bind = 1

# Increase connection tracking table size
net.netfilter.nf_conntrack_max = 131072

# Increase socket buffer sizes (for high throughput)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
EOF

    # 즉시 적용
    sysctl --system > /dev/null 2>&1
    echo -e "  ${GREEN}✓${NC} Created /etc/sysctl.d/99-volte-fuzzer.conf"
    echo -e "  ${GREEN}✓${NC} Applied sysctl settings"
}

# 3. SDR udev rules 설치
setup_sdr_udev() {
    echo -e "${YELLOW}[3/5] Installing SDR udev rules...${NC}"

    UDEV_DIR="/etc/udev/rules.d"

    # USRP (Ettus Research)
    cat > "$UDEV_DIR/99-usrp.rules" << 'EOF'
# USRP1
SUBSYSTEMS=="usb", ATTRS{idVendor}=="fffe", ATTRS{idProduct}=="0002", MODE:="0666"
# USRP2
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2500", ATTRS{idProduct}=="0002", MODE:="0666"
# USRP B100
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2500", ATTRS{idProduct}=="0001", MODE:="0666"
# USRP B200/B210
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2500", ATTRS{idProduct}=="0020", MODE:="0666"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2500", ATTRS{idProduct}=="0021", MODE:="0666"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2500", ATTRS{idProduct}=="0022", MODE:="0666"
# USRP X300/X310 (USB interface)
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2500", ATTRS{idProduct}=="0030", MODE:="0666"
EOF
    echo -e "  ${GREEN}✓${NC} Installed USRP udev rules"

    # LimeSDR
    cat > "$UDEV_DIR/99-limesdr.rules" << 'EOF'
# LimeSDR-USB
SUBSYSTEM=="usb", ATTR{idVendor}=="04b4", ATTR{idProduct}=="8613", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="04b4", ATTR{idProduct}=="00f1", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0403", ATTR{idProduct}=="601f", MODE="0666"
# LimeSDR-Mini
SUBSYSTEM=="usb", ATTR{idVendor}=="0403", ATTR{idProduct}=="6108", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6108", MODE="0666"
EOF
    echo -e "  ${GREEN}✓${NC} Installed LimeSDR udev rules"

    # BladeRF
    cat > "$UDEV_DIR/99-bladerf.rules" << 'EOF'
# BladeRF
SUBSYSTEM=="usb", ATTR{idVendor}=="2cf0", ATTR{idProduct}=="5246", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6066", MODE="0666"
# BladeRF 2.0
SUBSYSTEM=="usb", ATTR{idVendor}=="2cf0", ATTR{idProduct}=="5250", MODE="0666"
EOF
    echo -e "  ${GREEN}✓${NC} Installed BladeRF udev rules"

    # RTL-SDR (optional, for testing)
    cat > "$UDEV_DIR/99-rtlsdr.rules" << 'EOF'
# RTL-SDR
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2832", MODE:="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", MODE:="0666"
EOF
    echo -e "  ${GREEN}✓${NC} Installed RTL-SDR udev rules"

    # udev 규칙 리로드
    udevadm control --reload-rules
    udevadm trigger
    echo -e "  ${GREEN}✓${NC} Reloaded udev rules"
}

# 4. 실시간 스케줄링 권한
setup_realtime() {
    echo -e "${YELLOW}[4/5] Configuring realtime scheduling...${NC}"

    cat > /etc/security/limits.d/99-volte-realtime.conf << EOF
# VoLTE Fuzzer realtime scheduling permissions
# For SDR applications requiring low latency

*               soft    rtprio          99
*               hard    rtprio          99
*               soft    memlock         unlimited
*               hard    memlock         unlimited
*               soft    nofile          65535
*               hard    nofile          65535

# Docker group specific
@docker         soft    rtprio          99
@docker         hard    rtprio          99
@docker         soft    memlock         unlimited
@docker         hard    memlock         unlimited
EOF

    echo -e "  ${GREEN}✓${NC} Created /etc/security/limits.d/99-volte-realtime.conf"
    echo -e "  ${YELLOW}⚠ Note: Logout and login again to apply limits${NC}"
}

# 5. 기타 설정
setup_misc() {
    echo -e "${YELLOW}[5/5] Applying miscellaneous settings...${NC}"

    # TUN/TAP 권한
    if [ -c /dev/net/tun ]; then
        chmod 0666 /dev/net/tun
        echo -e "  ${GREEN}✓${NC} Set permissions on /dev/net/tun"
    fi

    # Docker가 설치되어 있으면 현재 사용자를 docker 그룹에 추가 알림
    if command -v docker &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Docker is installed"
        if [ -n "$SUDO_USER" ]; then
            if groups "$SUDO_USER" | grep -q docker; then
                echo -e "  ${GREEN}✓${NC} User '$SUDO_USER' is in docker group"
            else
                echo -e "  ${YELLOW}⚠ Run: sudo usermod -aG docker $SUDO_USER${NC}"
            fi
        fi
    else
        echo -e "  ${YELLOW}⚠ Docker not installed. Install with: sudo apt install docker.io docker-compose${NC}"
    fi

    # iptables 모드 확인
    if command -v update-alternatives &> /dev/null; then
        IPTABLES_MODE=$(update-alternatives --query iptables 2>/dev/null | grep "Value:" | awk '{print $2}' || echo "unknown")
        echo -e "  ${GREEN}✓${NC} iptables mode: $IPTABLES_MODE"
    fi
}

# 시스템 상태 확인
check_status() {
    echo -e "${CYAN}System Status Check${NC}"
    echo -e "${CYAN}===================${NC}"
    echo ""

    # 커널 모듈
    echo -e "${YELLOW}Kernel Modules:${NC}"
    for mod in sctp xt_RTPENGINE; do
        if lsmod | grep -q "^$mod"; then
            echo -e "  ${GREEN}✓${NC} $mod loaded"
        else
            echo -e "  ${RED}✗${NC} $mod not loaded"
        fi
    done
    echo ""

    # sysctl 설정
    echo -e "${YELLOW}Network Settings:${NC}"
    echo -e "  ip_forward:    $(sysctl -n net.ipv4.ip_forward)"
    echo -e "  rp_filter:     $(sysctl -n net.ipv4.conf.all.rp_filter)"
    echo -e "  ip_nonlocal_bind: $(sysctl -n net.ipv4.ip_nonlocal_bind 2>/dev/null || echo 'N/A')"
    echo ""

    # SDR 장치 확인
    echo -e "${YELLOW}USB Devices (SDR):${NC}"
    if command -v lsusb &> /dev/null; then
        # USRP
        if lsusb | grep -q "2500:"; then
            lsusb | grep "2500:" | while read line; do
                echo -e "  ${GREEN}✓${NC} USRP: $line"
            done
        fi
        # LimeSDR
        if lsusb | grep -qi "lime\|1d50:6108\|0403:6108"; then
            lsusb | grep -i "lime\|1d50:6108\|0403:6108" | while read line; do
                echo -e "  ${GREEN}✓${NC} LimeSDR: $line"
            done
        fi
        # BladeRF
        if lsusb | grep -q "2cf0:\|1d50:6066"; then
            lsusb | grep "2cf0:\|1d50:6066" | while read line; do
                echo -e "  ${GREEN}✓${NC} BladeRF: $line"
            done
        fi
        # 아무것도 없으면
        if ! lsusb | grep -qE "2500:|lime|1d50:6108|0403:6108|2cf0:|1d50:6066"; then
            echo -e "  ${YELLOW}⚠${NC} No supported SDR devices detected"
        fi
    else
        echo -e "  ${RED}✗${NC} lsusb not available"
    fi
    echo ""

    # Docker
    echo -e "${YELLOW}Docker:${NC}"
    if command -v docker &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Docker installed: $(docker --version)"
        if docker info &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} Docker daemon running"
        else
            echo -e "  ${RED}✗${NC} Docker daemon not running or permission denied"
        fi
    else
        echo -e "  ${RED}✗${NC} Docker not installed"
    fi
    echo ""

    # 리소스 제한
    echo -e "${YELLOW}Resource Limits:${NC}"
    echo -e "  Max open files: $(ulimit -n)"
    echo -e "  Max realtime priority: $(ulimit -r 2>/dev/null || echo 'N/A')"
}

# 도움말
show_help() {
    echo "Usage: sudo $0 [option]"
    echo ""
    echo "Options:"
    echo "  --all       Apply all settings (recommended)"
    echo "  --kernel    Setup kernel modules only"
    echo "  --network   Configure network settings only"
    echo "  --sdr       Install SDR udev rules only"
    echo "  --realtime  Configure realtime scheduling only"
    echo "  --check     Check current system status"
    echo "  --help      Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --all      # Full setup"
    echo "  sudo $0 --check    # Check status"
    echo ""
}

# 전체 설정 적용
setup_all() {
    setup_kernel_modules
    echo ""
    setup_network
    echo ""
    setup_sdr_udev
    echo ""
    setup_realtime
    echo ""
    setup_misc
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Setup complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Logout and login again (for limits to take effect)"
    echo "  2. Connect your SDR device"
    echo "  3. Run: ./run_epc.sh run"
    echo "  4. Run: ./run_enb.sh run"
    echo ""
}

# 메인
main() {
    case "${1:-}" in
        --all)
            check_root
            print_header
            check_ubuntu
            echo ""
            setup_all
            ;;
        --kernel)
            check_root
            print_header
            setup_kernel_modules
            ;;
        --network)
            check_root
            print_header
            setup_network
            ;;
        --sdr)
            check_root
            print_header
            setup_sdr_udev
            ;;
        --realtime)
            check_root
            print_header
            setup_realtime
            ;;
        --check)
            print_header
            check_status
            ;;
        --help|-h)
            show_help
            ;;
        "")
            print_header
            echo "No option specified. Run with --help for usage."
            echo ""
            echo "Quick options:"
            echo "  sudo $0 --all     # Full setup (recommended)"
            echo "  sudo $0 --check   # Check current status"
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run with --help for usage."
            exit 1
            ;;
    esac
}

main "$@"
