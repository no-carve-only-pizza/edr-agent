#!/bin/bash
# stress_test.sh - EDR 에이전트 스트레스 테스트
#
# 고부하 환경에서 ring_buffer 손실률(dropped events)을 유발해
# 에이전트의 안정성과 이벤트 처리 한계를 측정한다.
#
# 사용법:
#   sudo ./demo/stress_test.sh [지속시간(초)] [모드]
#   모드: exec | file | net | all (기본값: all)
#
# 예시:
#   sudo ./demo/stress_test.sh 60 all    # 60초 전체 부하 테스트
#   sudo ./demo/stress_test.sh 30 exec   # exec 폭탄만

DURATION="${1:-60}"
MODE="${2:-all}"
TMPDIR_STRESS=$(mktemp -d /tmp/edr_stress_XXXXX)

cleanup() {
    rm -rf "$TMPDIR_STRESS"
    # 백그라운드 자식 프로세스 정리
    kill 0 2>/dev/null
}
trap cleanup EXIT INT

echo "========================================"
echo "  EDR 에이전트 스트레스 테스트"
echo "  지속시간: ${DURATION}초  /  모드: ${MODE}"
echo "  에이전트 실행 확인: sudo ./build/edr-agent"
echo "========================================"

# ── exec 폭탄: 초당 수백 개의 프로세스 생성 ──────────────────────────────
exec_bomb() {
    local n="${1:-200}"
    for _ in $(seq 1 "$n"); do
        /bin/true &
    done
    wait
}

# ── 파일 쓰기 폭탄 ──────────────────────────────────────────────────────
file_bomb() {
    local n="${1:-500}"
    for i in $(seq 1 "$n"); do
        printf "stress_data_%d" "$i" > "$TMPDIR_STRESS/f_$i.dat"
    done
    # 생성한 파일 삭제 (delete 이벤트도 발생)
    rm -f "$TMPDIR_STRESS"/f_*.dat
}

# ── 네트워크 연결 폭탄: localhost 포트에 빠르게 연결 ─────────────────────
net_bomb() {
    local n="${1:-100}"
    # 연결 실패(ECONNREFUSED)도 connect() syscall은 발생한다
    for _ in $(seq 1 "$n"); do
        (timeout 0.05 bash -c 'echo > /dev/tcp/127.0.0.1/9999' 2>/dev/null || true) &
    done
    wait
}

# ── DNS 조회 폭탄 ────────────────────────────────────────────────────────
dns_bomb() {
    local domains=(example.com google.com github.com kernel.org debian.org)
    for d in "${domains[@]}"; do
        host "$d" > /dev/null 2>&1 &
    done
    wait
}

# ── 측정 루프 ─────────────────────────────────────────────────────────────
START=$(date +%s)
END=$((START + DURATION))

ITER=0
echo ""
echo "  [시작] $(date '+%H:%M:%S')"

while [ "$(date +%s)" -lt "$END" ]; do
    ITER=$((ITER + 1))

    case "$MODE" in
        exec) exec_bomb 300 ;;
        file) file_bomb 800 ;;
        net)  net_bomb  150 ;;
        all)
            exec_bomb 200 &
            file_bomb 400 &
            net_bomb  100 &
            dns_bomb       &
            wait
            ;;
    esac

    ELAPSED=$(( $(date +%s) - START ))
    printf "\r  반복: %-5d  경과: %ds / %ds" "$ITER" "$ELAPSED" "$DURATION"
done

echo ""
echo ""
echo "========================================"
echo "  완료: ${ITER}회 반복"
echo ""
echo "  결과 확인 방법:"
echo "  1. 에이전트 세션 통계(Ctrl+C 출력)에서 총 이벤트 수 확인"
echo "  2. 에이전트 stderr에서 'ring_buffer: X events lost' 메시지 확인"
echo "  3. 예상 이벤트 수와 실제 수의 차이 = 손실률"
echo ""
echo "  부하 수준 조정:"
echo "  - exec_bomb N: N 값을 늘리면 EXEC 이벤트 증가"
echo "  - file_bomb N: N 값을 늘리면 FILE 이벤트 증가"
echo "  - ring_buffer 크기: CMakeLists.txt에서 조정 가능"
echo "========================================"
