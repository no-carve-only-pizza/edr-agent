# EDR Agent (eBPF)

리눅스용 경량 EDR(Endpoint Detection & Response) 에이전트.  
eBPF 트레이스포인트로 **프로세스 실행 · 파일시스템 변경 · 네트워크 연결**을 실시간 감시하고, 탐지 룰 엔진을 통해 의심 행위를 분류한다.

## 아키텍처

```
BPF 커널 프로그램                    유저스페이스
─────────────────────────────────────────────────────
sched_process_exec   ─┐
sched_process_exit    │
sys_enter_execve      │  ring_buffer   match_rules()   stdout (table)
sys_enter_openat      ├─ (mmap)    ─▶  dedup_alerts() ─▶ NDJSON 파일
sys_enter_unlinkat    │              to_json()          HTTP POST
sys_enter_renameat2   │              HttpReporter
sys_enter_connect    ─┤
sys_exit_connect      │
sys_enter_bind       ─┘
```

## 탐지 룰

| ID | 이름 | 심각도 |
|---|---|---|
| R-001 | 시스템 경로 파일 수정 (`/etc/`, `/bin/` 등) | high |
| R-002 | 로그 파일 삭제 | high |
| R-003 | `/tmp` 경로 실행 (드로퍼 의심) | high |
| R-004 | 리버스셸/스캔 도구 실행 (`nc`, `socat` 등) | critical |
| R-005 | 스크립트 인터프리터 실행 | medium |
| R-006 | 비표준 포트 아웃바운드 연결 | medium |
| R-007 | 미지 프로세스 서버 포트 바인드 | low |
| R-008 | root 권한 인터프리터 실행 | critical |
| R-009 | `/tmp` → 시스템 경로 rename (TOCTOU 의심) | critical |
| R-010 | 인터프리터 `-c`/`-e` 인라인 페이로드 실행 (파일리스 공격 의심) | high |
| R-011 | 웹 서버 자식 셸 실행 (nginx/apache → bash, 웹셸 의심) | critical |
| R-012 | DB 서버 자식 셸 실행 (mysqld/postgres → bash, SQLi RCE 의심) | critical |

## 주요 기능

- **execve argv 캡처**: `sys_enter_execve` 훅으로 실행 인자 수집 (R-010 인라인 페이로드 탐지)
- **프로세스 트리 캐시**: 유저스페이스 pid→comm 맵, `/proc` 스캔으로 기존 데몬 사전 등록
- **부모 컨텍스트 탐지**: R-011/R-012 - 웹/DB 서버 자식 셸 실행 감지
- **화이트리스트 FP 억제**: 정상 프로세스(sshd, apt, dockerd 등) 노이즈 필터
- **알림 중복 억제**: (rule_id, comm) 키로 3초 윈도우 내 동일 룰 재발화 억제
- **성공 연결만 캡처**: `sys_exit_connect`로 반환값 확인 후 제출 (실패 연결 드롭)
- **UID → 사용자 이름**: `getpwuid_r()` 캐시로 UID=33 → `www-data` 표시
- **세션 통계**: Ctrl+C 시 총 이벤트 수, 룰별 발화 횟수 요약 출력

## 요구사항

- Linux 5.8+ (BPF ringbuf), BTF 지원 커널
- Ubuntu 22.04+ 기준

```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
     libcurl4-openssl-dev linux-tools-$(uname -r) cmake pkg-config
```

## 빌드

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## 실행

```bash
# 기본 (터미널 출력)
sudo ./build/edr-agent

# 전체 옵션
sudo ./build/edr-agent \
  --endpoint http://backend:8888/ingest \
  --token    YOUR_TOKEN \
  --log      /var/log/edr/events.ndjson \
  --alerts-only
```

## 이벤트 출력 예시

```
TYPE     TIME(s)    PID      USER          COMM              PATH / DEST
------------------------------------------------------------------------
[EXEC ]  1234.567s  PID=1234 PPID=999      root          sus_binary        /tmp/sus_binary
        argv: sus_binary
  >>> [ALERT] R-003 | /tmp 경로 실행 (드로퍼 의심)
[CONN ]  1234.590s  PID=1234 root          curl              → 1.2.3.4:9999
  >>> [ALERT] R-006 | 비표준 포트 아웃바운드 연결

=== 세션 통계 ===
총 이벤트: 1523  (EXEC=312  FILE=891  NET=320)

룰          발화 횟수
----------------------------
R-006       12 회
R-003        3 회
R-011        1 회
```

NDJSON 포맷 (`--log`):
```json
{"type":"exec","ts":1234.567,"pid":1234,"uid":0,"comm":"sus_binary","path":"/tmp/sus_binary","argv":["sus_binary"],"alerts":[{"id":"R-003","name":"/tmp 경로 실행 (드로퍼 의심)","sev":"high"}]}
```

## 프로젝트 구조

```
edr-agent/
├── CMakeLists.txt
├── include/
│   └── common.h              # BPF ↔ 유저스페이스 공유 구조체
├── bpf/
│   ├── process_monitor.bpf.c # sched_process_exec/exit, sys_enter_execve 훅
│   ├── file_monitor.bpf.c    # 파일시스템 syscall 훅
│   └── network_monitor.bpf.c # sys_enter/exit_connect, sys_enter_bind 훅
└── src/
    ├── main.cpp
    ├── proc_tree.h / proc_tree.cpp   # 프로세스 트리 캐시
    ├── rules/
    │   └── rule_engine.cpp   # 탐지 룰 데이터베이스 & 매칭
    └── output/
        ├── json_fmt.cpp      # NDJSON 직렬화
        └── http_reporter.cpp # libcurl HTTP POST 리포터
```

*소스코드: https://github.com/no-carve-only-pizza/edr-agent*
