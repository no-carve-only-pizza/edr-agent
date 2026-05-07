#!/bin/bash
# 시나리오 5: DNS 터널링 / DGA / 남용 TLD (R-018 트리거)
#
# iodine/dnscat2 같은 실제 도구 없이 dig/nslookup 으로 의심 패턴 재현.
# 실제 터널링 도구는 레이블을 50~62자로 채우므로 그와 유사한 쿼리를 보낸다.

echo "[demo] DNS 탐지 시나리오 (R-018a/b/c)"
echo ""

# R-018a: 레이블 > 50자 → DNS 터널링
echo "[demo 1] 긴 서브도메인 쿼리 (터널링 패턴)"
# 56자 Base32-like 서브도메인 = iodine/dnscat2 전형적 패턴
LONG_LABEL="aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgZm9yIGRucyB0dW5uZWxpbmc"
dig +time=1 +tries=1 "${LONG_LABEL}.example.com" A 2>/dev/null || true
sleep 1

# R-018b: 모음 없는 긴 랜덤 서브도메인 → DGA
echo "[demo 2] 모음 없는 랜덤 도메인 (DGA 패턴)"
dig +time=1 +tries=1 "xkqjsrplmbvntdhfgcwz.biz" A 2>/dev/null || true
sleep 1

# R-018c: 남용 TLD
echo "[demo 3] 남용 TLD 접속 (.tk/.ml)"
dig +time=1 +tries=1 "totally-legit-site.tk" A 2>/dev/null || true
dig +time=1 +tries=1 "free-download.ml" A 2>/dev/null || true

echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-018a/b/c 를 확인하세요."
echo "       (alert 있는 DNS 이벤트만 [DNS  ] 줄로 출력됩니다)"
