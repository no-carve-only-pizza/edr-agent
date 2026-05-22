#!/bin/bash
echo "[demo] python3 인라인 페이로드 실행"
echo "[demo] EDR이 R-005/R-010을 발화해야 합니다."
echo ""
python3 -c "import os; os.getcwd()" 2>/dev/null || true
sleep 0.5
perl -e "print 'test'" 2>/dev/null || true
echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-005/R-010을 확인하세요."
