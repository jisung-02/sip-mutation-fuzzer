#!/bin/bash
# VolteMutationFuzzer 실시간 감시 래퍼 스크립트

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRASH_ANALYZER="$SCRIPT_DIR/crash_analyzer.py"

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

show_usage() {
    cat << EOF
🔍 VolteMutationFuzzer 실시간 크래시 감시 도구

사용법:
  $0 [모드] [JSONL파일]

모드:
  watch     - 실시간 감시 (기본값)
  analyze   - 완료된 결과 분석
  latest    - 가장 최근 캠페인 자동 감시

예시:
  $0 watch results/campaign.jsonl          # 실시간 감시
  $0 analyze results/campaign.jsonl        # 배치 분석
  $0 latest                                 # 최신 결과 자동 감시

환경 설정:
  CRASH_ANALYSIS_INTERVAL=2.0              # 감시 간격 (초)
  CRASH_ANALYSIS_OUTPUT=crash_analysis     # 결과 출력 디렉토리
EOF
}

find_latest_campaign() {
    local latest_file=""
    local latest_time=0

    # results 디렉토리에서 최신 JSONL 파일 찾기
    for pattern in "results/*.jsonl" "results/*/*.jsonl"; do
        for file in $pattern; do
            if [ -f "$file" ]; then
                local file_time=$(stat -f %m "$file" 2>/dev/null || stat -c %Y "$file" 2>/dev/null || echo 0)
                if [ "$file_time" -gt "$latest_time" ]; then
                    latest_time=$file_time
                    latest_file="$file"
                fi
            fi
        done
    done

    echo "$latest_file"
}

check_prerequisites() {
    # Python3 확인
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python3 not found${NC}"
        return 1
    fi

    # tcpdump 확인 (pcap 분석용)
    if ! command -v tcpdump &> /dev/null; then
        echo -e "${YELLOW}⚠️  tcpdump not found - pcap analysis disabled${NC}"
    fi

    # crash_analyzer.py 확인
    if [ ! -f "$CRASH_ANALYZER" ]; then
        echo -e "${RED}❌ crash_analyzer.py not found at: $CRASH_ANALYZER${NC}"
        return 1
    fi

    return 0
}

run_realtime_watch() {
    local jsonl_file="$1"
    local interval="${CRASH_ANALYSIS_INTERVAL:-2.0}"
    local output_dir="${CRASH_ANALYSIS_OUTPUT:-crash_analysis}"

    echo -e "${BLUE}🔍 Starting realtime crash monitoring...${NC}"
    echo -e "${BLUE}📁 File: $jsonl_file${NC}"
    echo -e "${BLUE}⏱️  Interval: ${interval}s${NC}"
    echo -e "${BLUE}📊 Output: $output_dir${NC}"
    echo
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring and generate final report${NC}"
    echo

    # 실시간 감시 시작
    python3 "$CRASH_ANALYZER" "$jsonl_file" \
        --mode realtime \
        --interval "$interval" \
        --output "$output_dir"
}

run_batch_analysis() {
    local jsonl_file="$1"
    local output_dir="${CRASH_ANALYSIS_OUTPUT:-crash_analysis}"

    echo -e "${BLUE}📋 Analyzing completed fuzzing session...${NC}"
    echo -e "${BLUE}📁 File: $jsonl_file${NC}"
    echo -e "${BLUE}📊 Output: $output_dir${NC}"
    echo

    python3 "$CRASH_ANALYZER" "$jsonl_file" \
        --mode batch \
        --output "$output_dir"
}

watch_with_fuzzer() {
    local campaign_cmd="$1"
    local output_jsonl="$2"

    echo -e "${GREEN}🚀 Starting fuzzer with integrated monitoring...${NC}"
    echo -e "${BLUE}📝 Command: $campaign_cmd${NC}"
    echo -e "${BLUE}📁 Output: $output_jsonl${NC}"
    echo

    # 백그라운드에서 크래시 감시 시작
    local monitor_output="monitor_$(date +%H%M%S).log"
    python3 "$CRASH_ANALYZER" "$output_jsonl" \
        --mode realtime \
        --interval 3.0 > "$monitor_output" 2>&1 &
    local monitor_pid=$!

    echo -e "${GREEN}📊 Monitor started (PID: $monitor_pid)${NC}"
    echo -e "${YELLOW}🔥 Starting fuzzer...${NC}"

    # Fuzzer 실행
    if eval "$campaign_cmd"; then
        echo -e "${GREEN}✅ Fuzzer completed successfully${NC}"
    else
        echo -e "${RED}❌ Fuzzer failed${NC}"
    fi

    # Monitor 종료
    echo -e "${BLUE}🛑 Stopping monitor...${NC}"
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true

    echo -e "${BLUE}📋 Monitor log: $monitor_output${NC}"

    # 최종 배치 분석
    echo -e "${BLUE}📊 Generating final analysis...${NC}"
    run_batch_analysis "$output_jsonl"
}

main() {
    local mode="${1:-watch}"
    local jsonl_file="$2"

    # 도움말 표시
    if [ "$mode" = "-h" ] || [ "$mode" = "--help" ]; then
        show_usage
        exit 0
    fi

    # 전제조건 확인
    if ! check_prerequisites; then
        echo -e "${RED}❌ Prerequisites check failed${NC}"
        exit 1
    fi

    case "$mode" in
        "watch")
            if [ -z "${jsonl_file:-}" ]; then
                echo -e "${RED}❌ JSONL file required for watch mode${NC}"
                echo "Usage: $0 watch <jsonl_file>"
                exit 1
            fi

            if [ ! -f "$jsonl_file" ]; then
                echo -e "${YELLOW}⏳ Waiting for JSONL file to be created: $jsonl_file${NC}"

                # 파일이 생성될 때까지 대기 (최대 60초)
                local wait_count=0
                while [ ! -f "$jsonl_file" ] && [ $wait_count -lt 60 ]; do
                    sleep 1
                    wait_count=$((wait_count + 1))
                done

                if [ ! -f "$jsonl_file" ]; then
                    echo -e "${RED}❌ JSONL file not found after waiting: $jsonl_file${NC}"
                    exit 1
                fi
            fi

            run_realtime_watch "$jsonl_file"
            ;;

        "analyze")
            if [ -z "${jsonl_file:-}" ]; then
                echo -e "${RED}❌ JSONL file required for analyze mode${NC}"
                echo "Usage: $0 analyze <jsonl_file>"
                exit 1
            fi

            if [ ! -f "$jsonl_file" ]; then
                echo -e "${RED}❌ JSONL file not found: $jsonl_file${NC}"
                exit 1
            fi

            run_batch_analysis "$jsonl_file"
            ;;

        "latest")
            local latest_campaign=$(find_latest_campaign)

            if [ -z "$latest_campaign" ]; then
                echo -e "${RED}❌ No campaign JSONL files found in results/${NC}"
                echo "Start a fuzzing campaign first, or specify a file manually."
                exit 1
            fi

            echo -e "${GREEN}📁 Found latest campaign: $latest_campaign${NC}"
            run_realtime_watch "$latest_campaign"
            ;;

        "integrated")
            # 통합 모드: fuzzer와 함께 실행
            # 사용법: $0 integrated "fuzzer command" output.jsonl
            local campaign_cmd="$jsonl_file"
            local output_jsonl="$3"

            if [ -z "${campaign_cmd:-}" ] || [ -z "${output_jsonl:-}" ]; then
                echo -e "${RED}❌ Usage: $0 integrated \"<fuzzer_command>\" <output_jsonl>${NC}"
                exit 1
            fi

            watch_with_fuzzer "$campaign_cmd" "$output_jsonl"
            ;;

        *)
            echo -e "${RED}❌ Unknown mode: $mode${NC}"
            echo
            show_usage
            exit 1
            ;;
    esac
}

# 실행
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi