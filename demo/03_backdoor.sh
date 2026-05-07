#!/bin/bash
# 시나리오 3: 백도어 포트 바인드 (R-007 트리거)
#
# 공격자가 역방향 셸(reverse shell) 리스너를 여는 패턴.
# 비표준 포트(4444, 1337 등)에 바인드하면 R-007 이 발화한다.
# nc(netcat) 은 SHELL_TOOLS 에 포함되어 R-004 도 함께 발화.

echo "[demo] nc 로 비표준 포트(4444) 바인드 시도"
echo "[demo] EDR 이 R-004(리버스셸 도구) + R-007(포트 바인드) 를 발화해야 합니다."
echo ""

# timeout 으로 즉시 종료 (실제 연결 대기 없음)
timeout 1 nc -l -p 4444 2>/dev/null || true

echo ""

echo "[demo] 비표준 포트(4444)로 아웃바운드 연결 시도"
echo "[demo] EDR 이 R-006(비표준 포트 연결) 을 발화해야 합니다."
echo ""

# 연결 실패해도 BPF 훅은 sys_enter_connect 에서 이미 캡처
timeout 1 bash -c "echo '' | nc 127.0.0.1 4444" 2>/dev/null || true

echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-004 / R-006 / R-007 을 확인하세요."
