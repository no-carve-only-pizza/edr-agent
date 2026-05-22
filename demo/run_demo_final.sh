#!/bin/bash
# =============================================================================
# InsightGuard EDR - 최종 데모 스크립트
# 탐지 룰: R-001~R-020 중 12개 시나리오
# 사용법: sudo bash demo/run_demo_final.sh
# 에이전트 먼저 실행: sudo ./build/edr-agent --rules config/rules.yaml
# =============================================================================

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

print_header() {
    echo ""
    echo "======================================================"
    echo "  $1"
    echo "======================================================"
}

print_step() {
    echo ""
    echo "  [*] $1"
}

wait_user() {
    echo ""
    echo "  엔터 누르면 다음 시나리오로 넘어갑니다..."
    read -r
}

clear
echo "======================================================"
echo "  InsightGuard EDR Agent - 탐지 데모"
echo "  시나리오 12개 / 예상 소요시간: 약 5분"
echo "  에이전트 실행 확인 후 엔터를 눌러주세요."
echo "======================================================"
read -r

# ------------------------------------------------------------------------------
# 시나리오 1: R-001 - 시스템 경로 파일 수정
# ------------------------------------------------------------------------------
print_header "시나리오 1/12 | R-001 | 시스템 경로 파일 수정"
print_step "공격자가 /etc/ 경로에 파일을 생성합니다."
print_step "예상 알람: [ALERT] R-001"
echo ""

MARKER="/etc/edr_demo_marker_$$"
echo "edr_demo" | sudo tee "$MARKER" > /dev/null 2>&1 || true
sleep 1
sudo rm -f "$MARKER" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 2: R-002 - 로그 파일 삭제
# ------------------------------------------------------------------------------
print_header "시나리오 2/12 | R-002 | 로그 파일 삭제 (증거 인멸)"
print_step "공격자가 /var/log/ 파일을 삭제해 흔적을 지웁니다."
print_step "예상 알람: [ALERT] R-002"
echo ""

LOGFILE="/var/log/edr_demo_$$"
echo "edr_demo" | sudo tee "$LOGFILE" > /dev/null 2>&1 || true
sleep 0.5
sudo rm -f "$LOGFILE" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 3: R-003 - /tmp 드로퍼 실행
# ------------------------------------------------------------------------------
print_header "시나리오 3/12 | R-003 | /tmp 경로 실행 (드로퍼)"
print_step "공격자가 /tmp에 페이로드를 떨구고 실행합니다."
print_step "예상 알람: [ALERT] R-003"
echo ""

PAYLOAD="/tmp/edr_demo_payload_$$"
cp /bin/ls "$PAYLOAD"
chmod +x "$PAYLOAD"
"$PAYLOAD" /tmp > /dev/null 2>&1 || true
sleep 0.5
rm -f "$PAYLOAD"

wait_user

# ------------------------------------------------------------------------------
# 시나리오 4: R-004 + R-006 + R-007 - 리버스셸
# ------------------------------------------------------------------------------
print_header "시나리오 4/12 | R-004 + R-006 + R-007 | 리버스셸"
print_step "공격자가 nc로 비표준 포트(4444)에 리버스셸을 엽니다."
print_step "예상 알람: [ALERT] R-004, R-006, R-007"
echo ""

bash "$DEMO_DIR/03_backdoor.sh" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 5: R-005 + R-010 - 인터프리터 인라인 페이로드
# ------------------------------------------------------------------------------
print_header "시나리오 5/12 | R-005 + R-010 | 인터프리터 인라인 페이로드"
print_step "공격자가 python3 -c 로 인라인 코드를 실행합니다 (파일리스)."
print_step "예상 알람: [ALERT] R-005, R-010"
echo ""

python3 -c "import os; os.getcwd()" 2>/dev/null || true
sleep 0.5
perl -e "print 'test\n'" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 6: R-009 - /tmp → 시스템 경로 rename
# ------------------------------------------------------------------------------
print_header "시나리오 6/12 | R-009 | /tmp → 시스템 경로 이동 (TOCTOU)"
print_step "공격자가 /tmp 파일을 /etc/로 이동시킵니다."
print_step "예상 알람: [ALERT] R-009"
echo ""

TMP_FILE="/tmp/edr_demo_rename_$$"
TARGET="/etc/edr_demo_renamed_$$"
echo "test" > "$TMP_FILE"
sudo mv "$TMP_FILE" "$TARGET" 2>/dev/null || true
sleep 0.5
sudo rm -f "$TARGET" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 7: R-013 - LD_PRELOAD 인젝션
# ------------------------------------------------------------------------------
print_header "시나리오 7/12 | R-013 | LD_PRELOAD 인젝션"
print_step "공격자가 LD_PRELOAD로 악성 라이브러리를 주입합니다."
print_step "예상 알람: [ALERT] R-013"
echo ""

bash "$DEMO_DIR/01_ldpreload.sh" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 8: R-014 - ptrace 프로세스 추적
# ------------------------------------------------------------------------------
print_header "시나리오 8/12 | R-014 | ptrace 프로세스 추적"
print_step "공격자가 ptrace로 다른 프로세스를 추적/인젝션 시도합니다."
print_step "예상 알람: [ALERT] R-014"
echo ""

bash "$DEMO_DIR/04_ptrace.sh" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 9: R-015 - setuid 권한 상승
# ------------------------------------------------------------------------------
print_header "시나리오 9/12 | R-015 | 예상치 못한 setuid 실행"
print_step "공격자가 root 소유 setuid 바이너리로 권한을 상승시킵니다."
print_step "예상 알람: [ALERT] R-015"
echo ""

sudo cp /bin/sh /tmp/edr_demo_suid_$$
sudo chmod u+s /tmp/edr_demo_suid_$$
/tmp/edr_demo_suid_$$ -c "echo test" 2>/dev/null || true
sleep 0.3
sudo rm -f /tmp/edr_demo_suid_$$

wait_user

# ------------------------------------------------------------------------------
# 시나리오 10: R-017 - memfd_create 파일리스 공격
# ------------------------------------------------------------------------------
print_header "시나리오 10/12 | R-017 | memfd_create 파일리스 공격"
print_step "공격자가 메모리에서 직접 코드를 실행합니다 (디스크에 흔적 없음)."
print_step "예상 알람: [ALERT] R-017"
echo ""

bash "$DEMO_DIR/02_fileless.sh" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 11: R-018 - DNS 터널링
# ------------------------------------------------------------------------------
print_header "시나리오 11/12 | R-018 | DNS 터널링"
print_step "공격자가 DNS 쿼리로 데이터를 몰래 빼냅니다."
print_step "예상 알람: [ALERT] R-018"
echo ""

bash "$DEMO_DIR/05_dns_tunnel.sh" 2>/dev/null || true

wait_user

# ------------------------------------------------------------------------------
# 시나리오 12: R-020 - 드로퍼 C2 체인 (상관 분석)
# ------------------------------------------------------------------------------
print_header "시나리오 12/12 | R-020 | 드로퍼 C2 체인 (상관 분석)"
print_step "/tmp 실행 후 C2 서버로 아웃바운드 연결하는 다단계 공격입니다."
print_step "예상 알람: [ALERT] R-003, R-004, R-006, [CORRL] R-020"
echo ""

sudo cp /bin/bash /tmp/edr_demo_evil_$$
sudo chmod +x /tmp/edr_demo_evil_$$
/tmp/edr_demo_evil_$$ -c "nc 127.0.0.1 4444" 2>/dev/null || true
sleep 0.5
sudo rm -f /tmp/edr_demo_evil_$$

wait_user

# ------------------------------------------------------------------------------
# 완료
# ------------------------------------------------------------------------------
echo ""
echo "======================================================"
echo "  데모 완료!"
echo "  EDR 에이전트 세션 통계는 Ctrl+C로 확인하세요."
echo "======================================================"
