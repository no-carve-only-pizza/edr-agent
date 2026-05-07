# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-07  
**작성자:** (본인 이름)

---

## 1. 개요

본 보고서는 리눅스 엔드포인트에서 실시간으로 보안 이벤트를 수집·분석하는 EDR 에이전트의 1주차 개발 내용을 정리한다. 에이전트는 커널 수준에서 프로세스 실행, 파일시스템 변경, 네트워크 연결을 감시하고 탐지 룰 엔진을 통해 의심 행위를 분류한 뒤 팀 백엔드로 전달하는 역할을 담당한다.

---

## 2. 핵심 기술 선정: eBPF

### 2.1 탐지 기술 비교

리눅스에서 시스템 이벤트를 실시간으로 수집하는 방법은 크게 세 가지가 있다.

| 기술 | 이벤트 범위 | 오버헤드 | 커널 경로 |
|---|---|---|---|
| **eBPF** | 프로세스·파일·네트워크 전체 | 극소 | 커널 트레이스포인트 → ringbuf → mmap |
| Auditd | 대부분의 syscall | 중간~높음 | audit 프레임워크 → netlink → 데몬 |
| inotify | 파일시스템만 | 낮음 | VFS 레이어 훅 |

### 2.2 eBPF를 선택한 이유

**eBPF(extended Berkeley Packet Filter)**는 커널 5.8 이상에서 안정적으로 지원되는 커널 내 샌드박스 실행 환경이다. 아래 세 가지 이유로 EDR 에이전트의 핵심 기술로 채택하였다.

**① 단일 기술로 세 가지 이벤트 유형 커버**  
프로세스(sched 트레이스포인트), 파일(VFS syscall 트레이스포인트), 네트워크(소켓 syscall 트레이스포인트)를 동일한 프레임워크로 처리한다. Auditd와 inotify를 혼용하면 관리 복잡도가 배증된다.

**② 커널 verifier에 의한 안전성 보장**  
BPF 프로그램은 커널 로드 시 정적 검증기(verifier)가 다음을 보장한다: 모든 코드 경로 종료, 스택 사용량 512바이트 이하, 초기화되지 않은 메모리 접근 없음. 잘못 작성된 BPF 프로그램이 커널 크래시를 유발할 수 없다.

**③ Zero-copy 링버퍼(Ring Buffer)**  
커널 5.8에서 도입된 `BPF_MAP_TYPE_RINGBUF`는 커널이 이벤트를 기록하면 유저스페이스가 `mmap()`으로 매핑된 동일 물리 페이지를 직접 읽는다. 데이터 복사가 발생하지 않아 기존 `perf_event_output` 대비 메모리 효율이 높고 이벤트 순서가 보장된다.

---

## 3. 시스템 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│                         커널 공간                                │
│                                                                  │
│  sched_process_exec   sys_enter_openat    sys_enter_connect     │
│  (프로세스 실행)       sys_enter_unlinkat  sys_enter_bind        │
│                        sys_enter_renameat2                       │
│       │                      │                    │             │
│  BPF 프로그램 (JIT 컴파일, verifier 검증 완료)                   │
│       └──────────────────────┴────────────────────┘             │
│                              │                                   │
│                    BPF Ring Buffer (mmap)                        │
└──────────────────────────────┬───────────────────────────────────┘
                               │ zero-copy
┌──────────────────────────────▼───────────────────────────────────┐
│                       유저스페이스                                │
│                                                                  │
│   ring_buffer__poll()   ──▶   match_rules()   ──▶  출력         │
│   (epoll 기반 통합 폴링)        탐지 룰 엔진        ├─ stdout    │
│                                                     ├─ NDJSON   │
│                           to_json()                 └─ HTTP POST │
└──────────────────────────────────────────────────────────────────┘
```

세 개의 BPF 프로그램이 각자의 `ringbuf` 맵을 가지며, 유저스페이스에서는 `ring_buffer__add()`를 통해 단일 `epoll` 인스턴스에 등록한다. `ring_buffer__poll()` 호출 한 번으로 세 프로그램의 이벤트를 동시에 처리한다.

---

## 4. 구현 내용

### 4.1 파일 구조

```
edr-agent/
├── CMakeLists.txt
├── include/
│   └── common.h               # 커널 ↔ 유저 공유 구조체 및 상수
├── bpf/
│   ├── process_monitor.bpf.c  # 마일스톤 1
│   ├── file_monitor.bpf.c     # 마일스톤 2
│   └── network_monitor.bpf.c  # 마일스톤 3
└── src/
    ├── main.cpp               # 오케스트레이터
    ├── rules/
    │   └── rule_engine.cpp    # 마일스톤 4: 탐지 룰 엔진
    └── output/
        ├── json_fmt.cpp       # 마일스톤 4: NDJSON 직렬화
        └── http_reporter.cpp  # 마일스톤 5: HTTP 리포터
```

### 4.2 마일스톤 1: 프로세스 실행 모니터링

**BPF 훅:** `tp/sched/sched_process_exec`

`execve()` 시스템 콜이 새 바이너리를 프로세스의 가상 주소 공간(VAS)에 성공적으로 매핑한 직후 발화한다. 실패한 `execve()`는 트레이스포인트를 발화하지 않으므로 false-positive가 없다.

수집 정보: PID, PPID, UID, 타임스탬프, 프로세스 이름(comm), 실행 파일 경로

```
[EXEC ] 41264.408s  PID=1726399 PPID=1726398 UID=0  sus_binary  /tmp/sus_binary
```

**핵심 구현 포인트**

- `bpf_get_current_pid_tgid()` 반환값의 상위 32비트가 TGID(유저스페이스의 PID), 하위 32비트가 TID임에 주의. 리눅스 커널 내부에서는 PID와 TID의 의미가 유저스페이스와 반대로 쓰인다.
- 실행 파일 경로는 트레이스포인트 컨텍스트의 `__data_loc_filename` 필드에서 읽는다. 이 필드는 `[31:16]=길이`, `[15:0]=오프셋`으로 인코딩된 가변 길이 데이터 포인터이며 `bpf_probe_read_kernel_str()`로 안전하게 복사한다.
- 부모 PID는 `BPF_CORE_READ(task, real_parent, tgid)`로 획득. `BPF_CORE_READ()`는 CO-RE(Compile Once, Run Everywhere) 매크로로, `vmlinux.h`의 BTF 정보를 활용해 커널 버전별 구조체 오프셋 변화를 런타임에 자동 보정한다.

### 4.3 마일스톤 2: 파일시스템 변경 모니터링

**BPF 훅 3개:**

| 훅 | 감지 이벤트 |
|---|---|
| `tp/syscalls/sys_enter_openat` | 파일 쓰기/생성 (`O_WRONLY`, `O_CREAT`, `O_TRUNC` 플래그 필터링) |
| `tp/syscalls/sys_enter_unlinkat` | 파일/디렉터리 삭제 |
| `tp/syscalls/sys_enter_renameat2` | 파일 이름 변경/이동 |

```
[WRITE] 41264.412s  PID=1726403 UID=0  bash  [WRITE|CREAT|TRUNC] /etc/edr_test_file
[DELET] 41264.412s  PID=1726403 UID=0  rm    /etc/edr_test_file
[RENAM] 41264.143s  PID=1726797 UID=0  mv    /tmp/evil → /etc/cron.d/backdoor
```

**핵심 구현 포인트**

- `sys_enter_openat`의 `args[1]`은 유저스페이스 포인터이므로 `bpf_probe_read_user_str()`을 사용해야 한다. 커널 메모리용 `bpf_probe_read_kernel_str()`을 잘못 사용하면 SMAP(Supervisor Mode Access Prevention)에 의해 폴트가 발생한다.
- `renameat2()`는 원자적 파일 교체를 지원한다(`RENAME_EXCHANGE` 플래그). 이는 TOCTOU(Time-Of-Check-Time-Of-Use) 공격의 핵심 기법이므로 원본/대상 경로를 모두 수집한다.
- 읽기 전용 `open(O_RDONLY=0)`은 BPF 단계에서 필터링하여 이벤트 볼륨을 감소시킨다.

### 4.4 마일스톤 3: 네트워크 연결 모니터링

**BPF 훅 2개:**

| 훅 | 감지 이벤트 |
|---|---|
| `tp/syscalls/sys_enter_connect` | 아웃바운드 연결 시도 (TCP/UDP) |
| `tp/syscalls/sys_enter_bind` | 서버 소켓 바인드 |

```
[CONN ] 41264.415s  PID=1726404 UID=1000  curl  → 127.0.0.53:53
[CONN ] 41264.417s  PID=1726404 UID=1000  curl  → 104.20.23.154:9999
```

**핵심 구현 포인트**

- `sys_enter_connect`는 연결 성공 이전에 발화하므로 과정에서 PID를 정확히 얻을 수 있다. TCP의 경우 3-way handshake 완료(TCP_ESTABLISHED 상태 전이)는 softirq 컨텍스트에서 일어나 PID를 얻기 어렵다. `sys_enter_*` 훅이 EDR 목적에 더 적합하다.
- `sockaddr_in`/`sockaddr_in6`은 uapi 타입으로 `vmlinux.h`에 포함되지 않아 레이아웃을 직접 정의하였다. `sa_family` 2바이트를 먼저 읽어 AF_INET(2)/AF_INET6(10) 여부를 판별한 뒤 전체 구조체를 읽는 2단계 방식으로 구현한다.
- 포트는 네트워크 바이트 오더(big-endian)로 저장되어 유저스페이스 출력 시 `ntohs()`로 변환한다.

**`curl https://example.com` 한 번의 전체 네트워크 흐름 포착 결과:**

```
curl → 127.0.0.53:53         (로컬 DNS 리졸버 질의)
systemd-resolve → KT DNS:53  (실제 외부 DNS 질의)
curl → [IPv6]:443            (Happy Eyeballs: IPv6 우선 시도)
curl → 172.66.147.243:443    (IPv4 fallback, Cloudflare)
```

### 4.5 마일스톤 4: 탐지 룰 엔진

이벤트 스트림을 받아 악성 행위 패턴과 매칭하는 규칙 기반 탐지 엔진을 구현하였다.

**탐지 룰 목록**

| ID | 이름 | 대상 이벤트 | 심각도 |
|---|---|---|---|
| R-001 | 시스템 경로 파일 수정 | FILE_WRITE | high |
| R-002 | 로그 파일 삭제 | FILE_DELETE | high |
| R-003 | `/tmp` 경로 실행 (드로퍼) | PROC_EXEC | high |
| R-004 | 리버스셸/스캔 도구 실행 | PROC_EXEC | critical |
| R-005 | 스크립트 인터프리터 실행 | PROC_EXEC | medium |
| R-006 | 비표준 포트 아웃바운드 | NET_CONNECT | medium |
| R-007 | 서버 포트 바인드 | NET_BIND | low |
| R-008 | root 권한 인터프리터 실행 | PROC_EXEC | critical |
| R-009 | `/tmp` → 시스템 경로 rename | FILE_RENAME | critical |

**NDJSON 출력 예시** (alert 있는 이벤트):

```json
{
  "type": "exec",
  "ts": 41264.408,
  "pid": 1726399,
  "uid": 0,
  "comm": "sus_binary",
  "path": "/tmp/sus_binary",
  "alerts": [{"id":"R-003","name":"/tmp 경로 실행 (드로퍼 의심)","sev":"high"}]
}
```

JSON 직렬화는 외부 라이브러리 없이 RFC 8259 §7 규칙을 직접 구현하였다 (`"` → `\"`, 제어문자 → `\u00XX` 등).

### 4.6 마일스톤 5: HTTP 리포터

libcurl의 easy interface를 사용하여 이벤트를 팀 백엔드로 전송하는 리포터를 구현하였다.

- **형식:** NDJSON (`Content-Type: application/x-ndjson`) — 한 줄 = 하나의 완결된 JSON 오브젝트
- **배치 전송:** 이벤트 N개(기본 20개)를 버퍼링 후 일괄 POST
- **인증:** `Authorization: Bearer <token>` 헤더 지원
- **옵션:** `--alerts-only` 플래그로 alert가 있는 이벤트만 전송 가능

**실행 옵션:**

```bash
sudo ./edr-agent \
  --endpoint http://backend:8888/ingest \
  --token    YOUR_TOKEN \
  --log      /var/log/edr/events.ndjson \
  --alerts-only
```

---

## 5. 동작 확인

### 5.1 탐지 시나리오 실행 결과

아래 시나리오를 실행하여 모든 탐지 룰이 정상 발동됨을 확인하였다.

```bash
# 시나리오 1: /tmp 드로퍼 실행 (R-003)
cp /bin/ls /tmp/sus_binary && sudo /tmp/sus_binary /tmp

# 시나리오 2: 리버스셸 도구 실행 (R-004)
nc -h

# 시나리오 3: 민감 경로 파일 쓰기 (R-001)
sudo bash -c 'echo test > /etc/edr_test_file'

# 시나리오 4: 비표준 포트 연결 (R-006)
curl http://example.com:9999
```

**터미널 출력:**

```
[EXEC ] 41264.408s  PID=1726399 PPID=1726398 UID=0  sus_binary  /tmp/sus_binary
  >>> [ALERT] R-003 | /tmp 경로 실행 (드로퍼 의심)        [high]

[EXEC ] 41264.409s  PID=1726401 PPID=1726389 UID=1000  nc  /usr/bin/nc
  >>> [ALERT] R-004 | 리버스셸/스캔 도구 실행             [critical]

[WRITE] 41264.412s  PID=1726403 UID=0  bash  [WRITE|CREAT|TRUNC] /etc/edr_test_file
  >>> [ALERT] R-001 | 시스템 경로 파일 수정               [high]

[CONN ] 41264.417s  PID=1726404 UID=1000  curl  → 104.20.23.154:9999
  >>> [ALERT] R-006 | 비표준 포트 아웃바운드 연결          [medium]
```

### 5.2 빌드 환경

| 항목 | 내용 |
|---|---|
| OS | Ubuntu 24.04 (커널 6.17) |
| 컴파일러 | clang 18.1.3 (BPF), g++ 13.3.0 (유저스페이스) |
| 주요 라이브러리 | libbpf 1.3.0, libcurl 8.5.0 |
| 빌드 시스템 | CMake 3.28 |

### 5.3 소스코드

GitHub: **https://github.com/no-carve-only-pizza/edr-agent**

---

## 6. 기술적 고찰

### 6.1 BPF 스택 제한(512바이트)과 우회 방법

BPF 프로그램의 스택 크기는 커널에 의해 512바이트로 제한된다. `process_event`, `file_event`, `net_event` 구조체의 크기가 각각 296~552바이트에 달하므로 스택에 직접 선언하면 verifier가 거부한다. 이를 해결하기 위해 `bpf_ringbuf_reserve()`로 링버퍼 슬롯을 먼저 확보한 뒤 그 포인터에 데이터를 기록하는 방식을 사용한다.

### 6.2 CO-RE (Compile Once, Run Everywhere)

`bpftool btf dump file /sys/kernel/btf/vmlinux format c`로 생성한 `vmlinux.h`에는 실행 중인 커널의 모든 타입 정보가 BTF(BPF Type Format) 형태로 담겨 있다. `BPF_CORE_READ()` 매크로는 컴파일 시 필드 접근 정보를 `.BTF` ELF 섹션에 기록하고, 커널 로더가 실제 필드 오프셋으로 재배치한다. 덕분에 특정 커널 버전에서 컴파일한 BPF 오브젝트를 다른 버전의 커널에서도 재컴파일 없이 실행할 수 있다.

### 6.3 false-positive 현황

현재 구현에서 노이즈가 발생하는 케이스:

- `sys_enter_openat`은 `execve()` 성공 여부와 관계없이 발화 → 실패한 open도 포착됨
- VSCode Server, Firefox 등 백그라운드 프로세스의 파일 접근이 다수 출력됨
- R-007(서버 바인드)은 정상적인 서버 소켓도 탐지하여 FP 비율이 높음

---

## 7. 다음 주 계획

| 항목 | 내용 |
|---|---|
| execve argv 캡처 | `sys_enter_execve`에서 argv 배열을 읽어 인라인 페이로드 탐지 |
| 프로세스 트리 맵 | BPF 해시맵에 `pid → (ppid, comm)` 캐싱, 공격 체인 재구성 |
| 화이트리스트 | known-good 프로세스/경로 목록으로 false-positive 억제 |
| 백엔드 API 스펙 협의 | NDJSON 스키마 확정, 팀 수신 서버 구조 논의 |

---

*본 보고서의 모든 코드는 https://github.com/no-carve-only-pizza/edr-agent 에서 확인할 수 있다.*
