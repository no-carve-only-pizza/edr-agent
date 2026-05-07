# EDR Agent (eBPF)

리눅스용 경량 EDR(Endpoint Detection & Response) 에이전트.  
eBPF 트레이스포인트로 프로세스·파일·네트워크·메모리·DNS·네임스페이스 이벤트를 실시간 감시하고,  
단일 이벤트 룰 + 이벤트 상관 분석 + 위협 인텔리전스 피드 + EWMA 행동 이상 탐지로 **28가지 공격 패턴**을 탐지한다.

## 아키텍처

```
BPF 커널 프로그램 (6개)                유저스페이스
────────────────────────────────────────────────────────────────
process_monitor.bpf.c                  RuleConfig::load()  ← --rules rules.yaml
  sched_process_exec  ─┐               init_rules(cfg)
  sched_process_exit   │
  sys_enter_execve     │  ring_buffer   match_rules()       stdout (표)
file_monitor.bpf.c   ──┤  (mmap)    ─▶ dedup_alerts()   ─▶ NDJSON 파일
  openat/unlinkat      │              to_json()             HTTP POST
  renameat2            │                   │
network_monitor.bpf.c ─┤              CorrelationEngine  → [CORRL] 상관 패턴
  connect/bind         │              .feed(pid,evt,ts)
memory_monitor.bpf.c ──┤
  mmap/mprotect        │                   │
  memfd_create         │              FeedManager (백그라운드)
dns_monitor.bpf.c    ──┤  QNAME 파싱   ├─ Feodo Tracker IP → R-025
ns_monitor.bpf.c     ──┘  unshare()   ├─ URLhaus domain  → R-026
                                       └─ HashChecker (SHA-256) → R-027
                                       BehaviorProfiler (EWMA) → R-028
```

## 탐지 룰 (R-001 ~ R-028)

### 단일 이벤트 룰

| ID | 이름 | 심각도 |
|---|---|---|
| R-001 | 시스템 경로 파일 수정 (`/etc/`, `/bin/` 등) | high |
| R-002 | 로그 파일 삭제 (증거 인멸) | high |
| R-003 | `/tmp` 경로 실행 (드로퍼 의심) | high |
| R-004 | 리버스셸/스캔 도구 실행 (`nc`, `socat`, `nmap` 등) | critical |
| R-005 | 스크립트 인터프리터 실행 | medium |
| R-006 | 비표준 포트 아웃바운드 연결 | medium |
| R-007 | 미지 프로세스 서버 포트 바인드 | low |
| R-008 | root 권한 인터프리터 실행 | critical |
| R-009 | `/tmp` → 시스템 경로 rename (TOCTOU 의심) | critical |
| R-010 | 인터프리터 `-c`/`-e` 인라인 페이로드 (파일리스) | high |
| R-011 | 웹 서버 자식 셸 실행 (`nginx`/`apache` → `bash`) | critical |
| R-012 | DB 서버 자식 셸 실행 (`mysqld`/`postgres` → `bash`) | critical |
| R-013 | LD_PRELOAD 환경변수 인젝션 | high |
| R-014 | ptrace ATTACH — 프로세스 추적/인젝션 의심 | high |
| R-015 | 예상치 못한 setuid 바이너리 실행 | critical |
| R-016 | RWX 메모리 할당 (JIT 스프레이/셸코드) | high |
| R-017 | `memfd_create` 파일리스 공격 패턴 | critical/high |
| R-018a | DNS 터널링 (레이블 > 50자) | critical |
| R-018b | DGA 도메인 의심 (랜덤 서브도메인, 모음 비율 < 0.15) | high |
| R-018c | 남용 TLD 접속 (`.tk`/`.ml`/`.ga`/`.cf`/`.gq` 등) | medium |
| R-024 | 컨테이너 탈출 시도 (unshare + PID ns 비교) | critical/high |

### 위협 인텔리전스 룰 (R-025~R-027)

| ID | 이름 | 심각도 | 피드 소스 |
|---|---|---|---|
| R-025 | 알려진 C2 서버 IP 연결 | critical | Feodo Tracker (자동 갱신) |
| R-026 | 악성 도메인 DNS 조회 | critical | URLhaus (자동 갱신) |
| R-027 | 알려진 악성 파일 해시 실행 | critical | MalwareBazaar (config/known_hashes.txt) |

### EWMA 행동 이상 탐지 (R-028)

| ID | 지표 | 탐지 조건 | 심각도 |
|---|---|---|---|
| R-028 | net_connect / file_write / exec (60s 윈도우) | Z-점수 ≥ 3.0, 학습 윈도우 ≥ 3 | high |

### 이벤트 상관 분석 룰 (R-019~R-023)

같은 PID의 이벤트를 슬라이딩 윈도우(30~60초)로 추적해 다단계 공격 체인을 탐지한다.

| ID | 패턴 | 윈도우 | 심각도 |
|---|---|---|---|
| R-019 | ptrace ↔ memfd_create | 30s | critical |
| R-020 | /tmp 실행 ↔ 아웃바운드 연결 | 60s | critical |
| R-021 | /tmp 쓰기 → /tmp 실행 | 60s | critical |
| R-022 | RWX 메모리 ↔ 아웃바운드 연결 | 30s | critical |
| R-023 | 의심 DNS 조회 ↔ 아웃바운드 연결 | 30s | high |

## 주요 기능

- **6개 BPF 프로그램**: 프로세스/파일/네트워크/메모리/DNS/네임스페이스 동시 모니터링
- **execve argv 캡처**: `sys_enter_execve` 훅으로 인자 수집, R-010 인라인 페이로드 탐지
- **프로세스 트리 캐시**: `/proc` 스캔으로 기존 데몬 사전 등록, R-011/R-012 즉시 활성화
- **DNS BPF 파싱**: QNAME 와이어 포맷을 BPF 내부에서 직접 파싱 (AND 마스크로 Verifier 통과)
- **컨테이너 탐지**: CO-RE로 PID ns inum 읽기, init ns inum과 비교 (`/proc/1/ns/pid`)
- **이벤트 상관 분석**: PID별 deque 슬라이딩 윈도우, 5가지 다단계 공격 패턴 탐지
- **위협 인텔리전스 피드**: Feodo Tracker IP + URLhaus 도메인 주기적 자동 갱신 (백그라운드 스레드)
- **파일 해시 탐지**: SHA-256 헤더 전용 구현 + MalwareBazaar 해시 DB 대조 (R-027)
- **EWMA 행동 이상 탐지**: 프로세스별 연결/파일/exec 빈도 Z-점수 기반 이상 탐지 (R-028)
- **YAML 룰 외부화**: `--rules rules.yaml` 로 화이트리스트/블랙리스트/포트/피드 URL을 재컴파일 없이 교체
- **화이트리스트 FP 억제**: 정상 프로세스(sshd, apt, dockerd, gdb 등) 노이즈 필터
- **알림 중복 억제(dedup)**: (rule_id, comm) 키, 3초 윈도우 내 재발화 억제
- **NDJSON + HTTP POST**: libcurl로 백엔드 엔드포인트에 이벤트 전송, Bearer 토큰 인증
- **세션 통계**: Ctrl+C 시 이벤트 수·룰별 발화 횟수 요약

## 요구사항

- Linux 5.8+ (BPF ringbuf), BTF 지원 커널 (`/sys/kernel/btf/vmlinux` 존재)
- Ubuntu 22.04+ 기준

```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
     libcurl4-openssl-dev linux-tools-$(uname -r) cmake pkg-config
```

## 빌드

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## 실행

```bash
# 기본 (터미널 출력, 내장 기본 룰 사용)
sudo ./build/edr-agent

# 전체 옵션
sudo ./build/edr-agent \
  --rules    config/rules.yaml \        # YAML 룰 파일 (없으면 기본값)
  --endpoint http://backend:8888/ingest \
  --token    YOUR_TOKEN \
  --log      /var/log/edr/events.ndjson \
  --alerts-only                          # alert 있는 이벤트만 HTTP 전송
```

## 출력 예시

```
+----------------------------------------------------------------------+
|   EDR Agent  ·  Process + File + Network  (eBPF)                    |
|   Ctrl+C 로 종료                                                     |
+----------------------------------------------------------------------+
TYPE     TIME(s)    PID      USER          COMM              PATH / DEST
------------------------------------------------------------------------
[EXEC ]  1234.567s  PID=1234 PPID=999      root          evil              /tmp/evil
  [ALERT] R-003 | /tmp 경로 실행 (드로퍼 의심)
[CONN ]  1234.590s  PID=1234 root          evil              → 1.2.3.4:4444
  [ALERT] R-006 | 비표준 포트 아웃바운드 연결
[CORRL]  1234.590s  PID=1234 evil            ▶ 상관 패턴 탐지
  [ALERT] R-020 | 드로퍼 C2 체인: /tmp 실행 후 아웃바운드 연결
[UNSHR]  1235.000s  PID=2000 root          attacker          ns=[user mnt]  [IN CONTAINER]
  [ALERT] R-024 | 컨테이너 탈출 시도: 컨테이너 내 사용자 네임스페이스 분리
[DNS  ]  1236.000s  PID=3000 user          curl              AAAA...base64.c2.evil.tk
  [ALERT] R-018c | 남용 TLD 접속 (.tk/.ml/.ga 등)

=== 세션 통계 ===
총 이벤트: 4821  (EXEC=532 FILE=1823 NET=940 MEM=312 DNS=1200 NS=14)

룰          발화 횟수
----------------------------
R-006       28 회
R-003        5 회
R-020        3 회
R-024        1 회
```

NDJSON 포맷:
```json
{"type":"exec","ts":1234.567,"pid":1234,"uid":0,"comm":"evil","path":"/tmp/evil","argv":["evil"],"alerts":[{"id":"R-003","name":"/tmp 경로 실행 (드로퍼 의심)","sev":"high"}]}
{"type":"correlation","ts":1234.590,"pid":1234,"comm":"evil","alerts":[{"id":"R-020","name":"드로퍼 C2 체인: /tmp 실행 후 아웃바운드 연결","sev":"critical"}]}
{"type":"ns_unshare","ts":1235.000,"pid":2000,"uid":0,"comm":"attacker","ns_inum":4026532217,"flags":"0x10020000","in_container":true,"alerts":[{"id":"R-024","name":"컨테이너 탈출 시도: 컨테이너 내 사용자 네임스페이스 분리","sev":"critical"}]}
```

## YAML 룰 설정

`config/rules.yaml` 로 탐지 룰을 재컴파일 없이 수정할 수 있다.

```yaml
# 조직 환경에 맞게 수정
shell_tools:
  - nc
  - socat
  - custom-backdoor   # 추가

bind_whitelist:
  - sshd
  - my-internal-daemon  # 추가

common_ports:
  - 22
  - 443
  - 8443
  - 9999   # 내부 서비스 포트 추가
```

## 프로젝트 구조

```
edr-agent/
├── CMakeLists.txt
├── config/
│   ├── rules.yaml                  # 외부 YAML 룰 설정
│   └── known_hashes.txt            # 알려진 악성 파일 SHA-256 해시 DB
├── include/
│   └── common.h                    # BPF ↔ 유저스페이스 공유 구조체
├── bpf/
│   ├── process_monitor.bpf.c       # exec/exit/ptrace/envp 훅
│   ├── file_monitor.bpf.c          # 파일시스템 syscall 훅
│   ├── network_monitor.bpf.c       # connect/bind 훅
│   ├── memory_monitor.bpf.c        # mmap/mprotect/memfd 훅
│   ├── dns_monitor.bpf.c           # sendto UDP:53 + QNAME 파싱
│   └── ns_monitor.bpf.c            # unshare + PID ns 비교
├── src/
│   ├── main.cpp                    # 오케스트레이터 (BPF 로드·폴 루프)
│   ├── proc_tree.cpp/h             # 프로세스 트리 캐시
│   ├── rules/
│   │   ├── rule_engine.cpp/h       # 탐지 룰 매칭 로직
│   │   └── rule_config.cpp/h       # YAML 파서 + RuleConfig 구조체
│   ├── correlation/
│   │   └── correlator.cpp/h        # 슬라이딩 윈도우 상관 분석 엔진
│   ├── threat_intel/
│   │   ├── sha256.h                # SHA-256 헤더 전용 구현 (외부 의존성 없음)
│   │   ├── feed_manager.cpp/h      # Feodo Tracker IP + URLhaus 도메인 피드
│   │   └── hash_checker.cpp/h      # SHA-256 해시 DB 조회 (R-027)
│   ├── anomaly/
│   │   └── behavior_profiler.cpp/h # EWMA + Z-점수 행동 이상 탐지 (R-028)
│   └── output/
│       ├── json_fmt.cpp/h          # NDJSON 직렬화
│       └── http_reporter.cpp/h     # libcurl HTTP POST 리포터
└── demo/
    ├── run_demo.sh                 # 전체 데모 시나리오 실행
    ├── 01_ldpreload.sh             # R-013 LD_PRELOAD 시연
    ├── 02_fileless.sh              # R-017/R-022 파일리스 시연
    ├── 03_backdoor.sh              # R-004/R-006/R-007 시연
    ├── 04_ptrace.sh                # R-014/R-019 ptrace 시연
    └── 05_dns_tunnel.sh            # R-018 DNS 터널링 시연
```

*소스코드: https://github.com/no-carve-only-pizza/edr-agent*
