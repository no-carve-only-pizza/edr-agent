#!/bin/bash
# edr-ctl.sh - EDR 에이전트 능동 대응 제어 클라이언트
#
# 사용법:
#   ./edr-ctl.sh ping                # 에이전트 응답 확인
#   ./edr-ctl.sh status              # 이벤트 통계 조회
#   ./edr-ctl.sh kill <PID>          # 프로세스 강제 종료 (SIGKILL)
#   ./edr-ctl.sh kill <PID> <SIG>    # 지정 시그널 전송 (예: 15=SIGTERM)
#
# 요구사항: python3 (stdlib socket 사용, 외부 의존성 없음)

SOCK="${EDR_SOCK:-/run/edr-agent.sock}"

if [ $# -eq 0 ]; then
    echo "사용법: $0 <ping|status|kill> [PID] [SIG]"
    exit 1
fi

ACTION="$1"

case "$ACTION" in
    ping)
        JSON='{"action":"ping"}'
        ;;
    status)
        JSON='{"action":"status"}'
        ;;
    kill)
        if [ -z "$2" ]; then
            echo "[!] kill: PID 인자 필요"
            exit 1
        fi
        PID="$2"
        SIG="${3:-9}"
        JSON="{\"action\":\"kill\",\"pid\":$PID,\"sig\":$SIG}"
        ;;
    *)
        echo "[!] 알 수 없는 명령: $ACTION"
        exit 1
        ;;
esac

# python3의 표준 socket 모듈로 Unix 도메인 소켓 통신
python3 - "$SOCK" "$JSON" <<'EOF'
import sys, socket

sock_path = sys.argv[1]
payload   = sys.argv[2]

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall((payload + "\n").encode())
    resp = s.recv(4096).decode().strip()
    print(resp)
    s.close()
except FileNotFoundError:
    print(f"[!] 소켓 없음: {sock_path} (에이전트가 실행 중인지 확인)")
    sys.exit(1)
except ConnectionRefusedError:
    print(f"[!] 연결 거부: {sock_path}")
    sys.exit(1)
except Exception as e:
    print(f"[!] 오류: {e}")
    sys.exit(1)
EOF
