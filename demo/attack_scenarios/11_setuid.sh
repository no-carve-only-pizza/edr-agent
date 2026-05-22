#!/bin/bash
# 시나리오 11: 예상치 못한 setuid 바이너리 실행 (R-015 트리거)
#
# root 소유 + setuid 비트 설정된 바이너리를 화이트리스트 없는 이름으로 실행.
# uid(실제) ≠ euid(유효) 조건 충족 시 R-015 발화.

echo "[demo] root 소유 setuid 바이너리 생성 및 실행"
echo "[demo] EDR이 R-015(예상치 못한 setuid 실행)를 발화해야 합니다."
echo ""

sudo cp /bin/sh /tmp/testsetuid_$$
sudo chmod u+s /tmp/testsetuid_$$
/tmp/testsetuid_$$ -c "echo test" 2>/dev/null || true
sleep 0.3
sudo rm -f /tmp/testsetuid_$$

echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-015를 확인하세요."
