#!/bin/bash
echo "[demo] /tmp에 실행 파일 복사 후 실행"
echo "[demo] EDR이 R-003(/tmp 경로 실행)을 발화해야 합니다."
echo ""
PAYLOAD="/tmp/edr_test_payload_$$"
cp /bin/ls "$PAYLOAD"
chmod +x "$PAYLOAD"
"$PAYLOAD" /tmp > /dev/null 2>&1 || true
rm -f "$PAYLOAD"
echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-003을 확인하세요."
