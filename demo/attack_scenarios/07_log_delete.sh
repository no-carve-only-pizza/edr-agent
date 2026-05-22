#!/bin/bash
echo "[demo] /var/log/에 테스트 파일 생성 후 삭제"
echo "[demo] EDR이 R-002(로그 파일 삭제)를 발화해야 합니다."
echo ""
LOGFILE="/var/log/edr_test_$$"
echo "edr_test" | sudo tee "$LOGFILE" > /dev/null 2>&1 || true
sleep 0.3
sudo rm -f "$LOGFILE" 2>/dev/null || true
echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-002를 확인하세요."
