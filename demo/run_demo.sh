#!/bin/bash
# EDR Agent 종합 데모 런너
#
# 사전 조건:
#   1) sudo ./build/edr-agent [--log /tmp/edr_demo.log] 를 다른 터미널에서 먼저 실행
#   2) 이 스크립트는 루트 권한 불필요 (일부 시나리오는 EPERM 으로 의도적 실패)
#
# 사용법:
#   cd /path/to/edr-agent
#   ./demo/run_demo.sh

set -euo pipefail
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
RST='\033[0m'

step() {
    local num="$1" title="$2" rules="$3"
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo -e "${YLW}시나리오 $num: $title${RST}"
    echo -e "  예상 알림: ${RED}$rules${RST}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    sleep 1
}

echo -e "${GRN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║         EDR Agent 공격 시나리오 데모             ║"
echo "║  EDR 터미널에서 알림([ALERT])을 확인하세요       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${RST}"
sleep 1

step 1 "LD_PRELOAD 인젝션" "R-013 (high)"
bash "$DEMO_DIR/01_ldpreload.sh"
sleep 2

step 2 "memfd_create 파일리스 공격" "R-017 (critical)"
bash "$DEMO_DIR/02_fileless.sh"
sleep 2

step 3 "백도어 포트 바인드 / 비표준 연결" "R-004 (critical), R-006 (medium), R-007 (low)"
bash "$DEMO_DIR/03_backdoor.sh"
sleep 2

step 4 "ptrace ATTACH (프로세스 추적 의심)" "R-014 (high)"
bash "$DEMO_DIR/04_ptrace.sh"
sleep 2

step 5 "DNS 터널링 / DGA / 남용 TLD" "R-018a (critical), R-018b (high), R-018c (medium)"
bash "$DEMO_DIR/05_dns_tunnel.sh"
sleep 1

echo ""
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${GRN}데모 완료.${RST}"
echo "EDR 터미널에서 Ctrl+C 로 종료하면 세션 통계가 출력됩니다."
