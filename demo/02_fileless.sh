#!/bin/bash
# 시나리오 2: memfd_create 파일리스 공격 (R-017 트리거)
#
# memfd_create() 로 파일시스템에 흔적을 남기지 않는 익명 파일을 생성.
# 실제 공격: memfd_create → write(셸코드) → fexecve(fd) 순서.
# 데모에서는 fexecve 없이 fd 생성/쓰기까지만 수행 (시스템 안전 유지).

echo "[demo] memfd_create() 파일리스 메모리 파일 생성 시도"
echo "[demo] EDR 이 R-017 알림을 발화해야 합니다."
echo ""

python3 - << 'PYEOF'
import ctypes, os, sys

libc = ctypes.CDLL(None, use_errno=True)

# sys_memfd_create = 319 (x86_64)
# name="" (빈 이름 = 은닉 의도), flags=MFD_ALLOW_SEALING(0x2) → critical 조건
SYS_memfd_create = 319
MFD_ALLOW_SEALING = 0x2

fd = libc.syscall(SYS_memfd_create, b"", MFD_ALLOW_SEALING)
if fd < 0:
    errno = ctypes.get_errno()
    print(f"[demo] memfd_create 실패: errno={errno}")
    sys.exit(1)

print(f"[demo] memfd_create() 성공: fd={fd}")
print(f"[demo] /proc/self/fd/{fd} = ", end="")
try:
    print(os.readlink(f"/proc/self/fd/{fd}"))
except:
    print("(읽기 실패)")

# 데모 페이로드 기록 (실제 셸코드 대신 마커 문자열)
payload = b"\x90" * 16 + b"[DEMO_PAYLOAD_MARKER]"
os.write(fd, payload)
print(f"[demo] {len(payload)} 바이트 페이로드 기록 완료 (fexecve 는 데모에서 생략)")
os.close(fd)
PYEOF

echo ""
echo "[demo] 완료 - EDR 출력에서 [ALERT] R-017 을 확인하세요."
