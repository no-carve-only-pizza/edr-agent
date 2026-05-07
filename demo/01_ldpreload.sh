#!/bin/bash
# 시나리오 1: LD_PRELOAD 인젝션 (R-013 트리거)
#
# LD_PRELOAD 로 공유 라이브러리를 먼저 로드해 libc 함수를 후킹하는 패턴.
# 실제 공격에서는 readdir(), open() 등을 후킹해 파일/프로세스를 은닉한다.

set -e
TMPDIR_DEMO=$(mktemp -d)
trap "rm -rf $TMPDIR_DEMO" EXIT

cat > "$TMPDIR_DEMO/evil_hook.c" << 'EOF'
#include <stdio.h>
/* puts() 후킹: echo 명령이 내부적으로 호출하는 puts 가로채기 */
int puts(const char *s) {
    printf("[HOOKED] puts(\"%s\") 가로챔\n", s);
    return 0;
}
EOF

gcc -shared -fPIC -nostartfiles -o "$TMPDIR_DEMO/evil_hook.so" "$TMPDIR_DEMO/evil_hook.c"

echo "[demo] LD_PRELOAD=$TMPDIR_DEMO/evil_hook.so 로 /bin/echo 실행"
echo "[demo] EDR 이 R-013 알림을 발화해야 합니다."
echo ""

LD_PRELOAD="$TMPDIR_DEMO/evil_hook.so" /bin/echo "정상 출력 문자열"

echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-013 을 확인하세요."
