#!/bin/bash
echo "[demo] /tmp에서 /etc/로 파일 이동 시도"
echo "[demo] EDR이 R-009(/tmp → 시스템 경로 rename)를 발화해야 합니다."
echo ""
TMP_FILE="/tmp/edr_test_rename_$$"
TARGET="/etc/edr_test_renamed_$$"
echo "test" > "$TMP_FILE"
sudo mv "$TMP_FILE" "$TARGET" 2>/dev/null || true
sleep 0.3
sudo rm -f "$TARGET" 2>/dev/null || true
echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-009를 확인하세요."
