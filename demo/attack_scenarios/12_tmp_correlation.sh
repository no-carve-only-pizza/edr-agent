#!/bin/bash
echo "[demo] /tmp 쓰기 → 실행 → 아웃바운드 연결 체인"
echo "[demo] EDR이 R-020/R-021을 발화해야 합니다."
echo ""
PAYLOAD="/tmp/edr_chain_$$"

echo "[+] Step 1: /tmp에 페이로드 쓰기"
cat > "$PAYLOAD" << 'INNER'
#!/bin/bash
echo "payload running"
timeout 1 bash -c "echo '' | nc 127.0.0.1 4444" 2>/dev/null || true
INNER
chmod +x "$PAYLOAD"
sleep 0.5

echo "[+] Step 2: 페이로드 실행 (같은 프로세스에서 연결까지)"
"$PAYLOAD"

rm -f "$PAYLOAD"
echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-020/R-021을 확인하세요."
