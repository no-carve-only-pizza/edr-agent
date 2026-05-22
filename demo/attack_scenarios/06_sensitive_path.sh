#!/bin/bash
echo "[demo] 민감 경로(/etc/)에 파일 생성 시도"
echo "[demo] EDR이 R-001(시스템 경로 파일 수정)을 발화해야 합니다."
echo ""
MARKER="/etc/edr_test_marker_$$"
echo "edr_test" | sudo tee "$MARKER" > /dev/null 2>&1 || true
sleep 0.5
sudo rm -f "$MARKER" 2>/dev/null || true
echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-001을 확인하세요."
