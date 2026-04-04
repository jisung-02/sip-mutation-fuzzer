#!/bin/bash
#
# srsRAN 4G 초기화 스크립트
# eNodeB를 COMPONENT_NAME 환경변수에 따라 실행
#

set -e

echo "=== srsRAN 4G Initialization ==="
echo "COMPONENT_NAME: ${COMPONENT_NAME}"

# IP 주소 확인
export IP_ADDR=$(hostname -I | awk '{print $1}')
echo "Container IP: ${IP_ADDR}"

# 설정 파일 확인
if [ -d "/etc/srsran" ] && [ "$(ls -A /etc/srsran 2>/dev/null)" ]; then
    echo "Using mounted configuration from /etc/srsran"
else
    echo "Using default srsRAN configuration"
fi

# 환경 변수로 설정 파일 업데이트
update_config() {
    local file=$1
    if [ -f "$file" ]; then
        echo "Updating config: $file"
        # MCC, MNC
        [ -n "$MCC" ] && sed -i "s/^mcc = .*/mcc = ${MCC}/" "$file"
        [ -n "$MNC" ] && sed -i "s/^mnc = .*/mnc = ${MNC}/" "$file"
        # MME 주소
        [ -n "$MME_IP" ] && sed -i "s/^mme_addr = .*/mme_addr = ${MME_IP}/" "$file"
        # eNB 바인딩 주소 (컨테이너 IP 사용)
        [ -n "$IP_ADDR" ] && sed -i "s/^gtp_bind_addr = .*/gtp_bind_addr = ${IP_ADDR}/" "$file"
        [ -n "$IP_ADDR" ] && sed -i "s/^s1c_bind_addr = .*/s1c_bind_addr = ${IP_ADDR}/" "$file"
    fi
}

update_rr_config() {
    local file=$1
    if [ -f "$file" ]; then
        echo "Updating RR config: $file"
        # TAC 업데이트 (16진수로 변환)
        if [ -n "$TAC" ]; then
            TAC_HEX=$(printf "0x%04x" "$TAC")
            sed -i "s/tac = 0x[0-9a-fA-F]*/tac = ${TAC_HEX}/" "$file"
        fi
    fi
}

# 컴포넌트별 실행
case $COMPONENT_NAME in
    enb|srsenb)
        echo "Starting srsENB..."

        # 설정 파일 확인
        if [ -f "/etc/srsran/enb.conf" ]; then
            CONFIG_FILE="/etc/srsran/enb.conf"
        else
            CONFIG_FILE="/root/.config/srsran/enb.conf"
        fi

        # 환경 변수로 설정 파일 업데이트
        update_config "$CONFIG_FILE"
        update_rr_config "/etc/srsran/rr.conf"

        echo "Config file: ${CONFIG_FILE}"
        exec srsenb ${CONFIG_FILE} "$@"
        ;;

    *)
        echo "Unknown component: ${COMPONENT_NAME}"
        echo "Valid options: enb, srsenb"
        echo ""
        echo "Starting bash shell for debugging..."
        exec /bin/bash
        ;;
esac
