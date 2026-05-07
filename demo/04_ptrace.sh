#!/bin/bash
# 시나리오 4: ptrace ATTACH (R-014 트리거)
#
# gdb/strace 는 PTRACE_WHITELIST 에 있어 알림이 발화하지 않는다.
# evil_attach 는 화이트리스트 외 바이너리이므로 R-014 를 발화시킨다.
# 권한 없는 PID 에 attach 하면 EPERM 으로 실패하지만
# BPF 훅은 sys_enter_ptrace 에서 시도 자체를 캡처한다.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# evil_attach 컴파일 (없으면)
if [ ! -f "$SCRIPT_DIR/evil_attach" ]; then
    echo "[demo] evil_attach 컴파일 중..."
    gcc -o "$SCRIPT_DIR/evil_attach" "$SCRIPT_DIR/evil_attach.c"
fi

# 추적 대상: PID 1 (init/systemd) - 권한 없으면 EPERM, 있으면 attach 후 detach
TARGET_PID=1
echo "[demo] evil_attach 로 PID $TARGET_PID 에 ptrace ATTACH 시도"
echo "[demo] EDR 이 R-014(ptrace 의심) 을 발화해야 합니다."
echo ""

"$SCRIPT_DIR/evil_attach" "$TARGET_PID"

echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-014 를 확인하세요."
