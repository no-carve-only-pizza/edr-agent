# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-21  
**작성자:** (본인 이름)

---

## 1. 개요

2주차까지 핵심 탐지 기능(R-001~R-012, argv 캡처, 프로세스 트리, 화이트리스트)을 완성하였다. 3주차에는 **탐지 품질 개선**, **코드 보안 강화**, **운영 편의성 향상** 세 방향으로 작업을 진행하였다.

1. **프로세스 종료 이벤트(`sched_process_exit`) 훅**: 프로세스 종료 시 트리 캐시 자동 정리
2. **알림 중복 억제(dedup)**: 동일 룰의 단시간 반복 발화를 3초 윈도우로 억제
3. **graceful shutdown**: Ctrl+C 시 링버퍼 드레인 후 안전 종료
4. **HTTP 헤더 인젝션 취약점 수정**: token 인자의 CR/LF 제거
5. **`sys_exit_connect` 훅**: 성공한 연결만 캡처하여 실패 노이즈 제거
6. **UID → 사용자 이름 변환**: getpwuid_r() 기반 캐시로 UID 숫자를 이름으로 표시
7. **세션 통계 출력**: 종료 시 총 이벤트 수, 룰별 발화 횟수 요약

---

## 2. 구현 내용

### 2.1 프로세스 종료 이벤트 훅 + ProcTree 정리

#### 2.1.1 문제

2주차에 구현한 `ProcTree`는 `sched_process_exec` 이벤트로 PID를 등록하지만, 종료된 프로세스를 제거하는 메커니즘이 없었다. 장기 실행 시 `std::unordered_map`이 무한히 증가하고, 리눅스의 PID 재사용으로 인해 새 프로세스가 이전 프로세스의 comm을 상속받는 오탐 가능성이 있었다.

#### 2.1.2 구현

`process_monitor.bpf.c`에 `sched_process_exit` 트레이스포인트를 추가하고, 전용 링버퍼 `rb_exit`를 통해 유저스페이스에 종료 이벤트를 전달한다.

```c
SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)pid_tgid;

    /* 스레드 종료는 무시 - 프로세스 리더만 처리 */
    if (tgid != tid)
        return 0;

    struct exit_event *e = bpf_ringbuf_reserve(&rb_exit, sizeof(*e), 0);
    if (!e) return 0;

    e->pid       = tgid;
    e->ts_ns     = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = BPF_CORE_READ(task, exit_code);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

유저스페이스의 `handle_exit_event`에서 `g_proc_tree.remove(e.pid)`를 호출하여 캐시 항목을 즉시 제거한다.

#### 2.1.3 스레드 필터링

`sched_process_exit`는 스레드 종료 시에도 발화한다. 멀티스레드 프로세스에서 하나의 워커 스레드가 종료될 때마다 PID가 트리에서 제거되면 안 된다. `bpf_get_current_pid_tgid()`로 TID(하위 32비트)와 TGID(상위 32비트)를 비교하여 TGID가 TID와 같은 경우(메인 스레드 종료)만 이벤트를 전달한다.

```
exec_event  → ProcTree 등록   (sched_process_exec)
exit_event  → ProcTree 제거   (sched_process_exit, 메인 스레드만)
```

---

### 2.2 알림 중복 억제 (dedup)

#### 2.2.1 문제

1주차~2주차 구현에서 다음과 같은 노이즈 패턴이 관찰되었다.

| 상황 | 발화 룰 | 횟수 |
|---|---|---|
| `systemd` 시작 시 sshd/nginx 포트 바인드 | R-007 | 5~10회 연속 |
| `pip install` 실행 중 | R-005/R-008 | 수십 회 |
| `apt upgrade` 실행 중 | R-001 | 수십 회 |

화이트리스트로 일부 억제했지만, 화이트리스트에 없는 프로세스가 같은 룰을 짧은 시간 안에 반복 트리거하는 경우를 처리하지 못했다.

#### 2.2.2 구현

`(rule_id, comm)` 쌍을 키로 마지막 발화 타임스탬프를 기록하고, 3초 이내 재발화를 억제한다.

```cpp
static std::unordered_map<std::string, uint64_t> g_dedup;
static constexpr uint64_t DEDUP_NS = 3ULL * 1'000'000'000ULL;

static std::vector<RuleMatch> dedup_alerts(std::vector<RuleMatch> hits,
                                            const char *comm, uint64_t ts_ns)
{
    auto end = std::remove_if(hits.begin(), hits.end(),
        [&](const RuleMatch &h) {
            std::string key = std::string(h.id) + ":" + comm;
            auto it = g_dedup.find(key);
            if (it != g_dedup.end() && ts_ns - it->second < DEDUP_NS)
                return true;
            g_dedup[key] = ts_ns;
            return false;
        });
    hits.erase(end, hits.end());
    return hits;
}
```

**PID가 아닌 comm으로 키잉하는 이유:** PID는 재사용될 수 있고, 같은 종류의 프로세스 인스턴스가 여럿 동시에 같은 룰을 트리거할 때 전부 억제하는 것이 의도된 동작이다. 예를 들어 `python3` 인스턴스 10개가 각각 `-c` 플래그로 실행되면 3초 내에는 R-010이 한 번만 출력된다.

---

### 2.3 graceful shutdown

이벤트 폴 루프가 SIGINT/SIGTERM으로 종료될 때, 링버퍼에 아직 처리되지 않은 이벤트가 남아 있을 수 있다. `ring_buffer__poll(timeout=100ms)` 다음 폴 이전에 종료 신호가 수신되면 최대 100ms 분량의 이벤트가 유실된다.

```cpp
while (g_running) {
    err = ring_buffer__poll(rb, 100);
    ...
}

printf("\n[*] 종료 중...\n");
ring_buffer__consume(rb);      /* 남은 이벤트 전부 처리 */
if (g_reporter) g_reporter->flush();
```

`ring_buffer__consume()`은 타임아웃 없이 현재 버퍼에 있는 모든 이벤트를 즉시 처리한다. 이후 `HttpReporter::flush()`로 HTTP 버퍼도 비운다.

---

### 2.4 HTTP 헤더 인젝션 취약점 수정

#### 2.4.1 취약점 분석

`http_reporter.cpp`에서 `--token` 인자를 직접 `Authorization` 헤더에 삽입하였다.

```cpp
// 취약한 코드
std::string auth = "Authorization: Bearer " + token_;
headers = curl_slist_append(headers, auth.c_str());
```

공격자가 `--token "foo\r\nX-Injected: bar"` 와 같은 값을 전달하면 임의의 HTTP 헤더를 삽입할 수 있다. 이 도구가 root 권한으로 실행되는 EDR 에이전트인 만큼, 설정 파일이나 스크립트를 통한 인자 변조가 발생할 경우 백엔드 서버에 대한 헤더 조작이 가능하다.

#### 2.4.2 수정

생성자에서 CR/LF 문자를 제거한다.

```cpp
// http_reporter.cpp 생성자
token_.erase(std::remove_if(token_.begin(), token_.end(),
    [](char c){ return c == '\r' || c == '\n'; }), token_.end());
```

보안 동아리 프로젝트로서 코드베이스 전체를 점검한 결과, 그 외 취약점은 발견되지 않았다:
- `gets()`, 경계 없는 `sprintf()`, `strcpy()` 미사용
- 모든 `snprintf()` 호출에 `sizeof(buf)` 명시
- `strncpy()` 사용 시 명시적 NUL 종단 (`buf[N-1] = '\0'`)
- BPF 코드: `bpf_probe_read_user*()` API로만 유저 메모리 접근, AND 마스크로 오프셋 경계 보장

---

### 2.5 `sys_exit_connect` 훅 - 성공한 연결만 캡처

#### 2.5.1 문제

기존 `sys_enter_connect` 훅은 연결 시도 시점에 발화하므로 실패한 연결(ECONNREFUSED, ETIMEDOUT 등)도 이벤트로 기록된다. 특히 `curl`, `apt` 등이 여러 서버를 순차 시도하거나 DNS 조회 실패 후 재시도할 때 대량의 노이즈가 발생한다.

#### 2.5.2 두 훅 패턴

```
sys_enter_connect:  sockaddr 파싱 → pending_connect[TID] 에 net_event 저장
                    (이 시점에만 sockaddr 유저 포인터가 유효)

sys_exit_connect:   반환값(ctx->ret) 확인
                    ret == 0          → 즉시 성공 (UDP, 이미 연결된 TCP)
                    ret == -EINPROGRESS(-115) → 논블로킹 TCP SYN 전송됨
                    그 외             → 실패 → pending 삭제 후 드롭

                    성공 시: pending_connect 에서 복사 → ringbuf 제출
                             ts_ns 를 연결 완료 시각으로 갱신
```

`pending_connect` 맵은 TID를 키로 사용한다. PID(TGID)가 아닌 TID를 사용하는 이유는, 멀티스레드 프로세스에서 두 스레드가 동시에 `connect()`를 호출할 때 PID로 키잉하면 데이터가 덮어쓰이기 때문이다.

**EINPROGRESS를 성공으로 분류하는 이유:** 논블로킹 소켓은 `connect()` 호출 시 즉시 `-EINPROGRESS`를 반환하고 이후 `poll`/`epoll`로 완료를 기다린다. 공격자가 사용하는 역방향 셸, 포트 스캐너 등은 대부분 논블로킹 소켓을 사용하므로 이를 포함하지 않으면 핵심 위협 시나리오가 누락된다.

---

### 2.6 UID → 사용자 이름 변환

`getpwuid_r()` (thread-safe)로 UID를 사람이 읽을 수 있는 이름으로 변환한다. 정적 `std::unordered_map` 캐시로 동일 UID의 반복 조회를 방지한다.

```cpp
static const char *uid_name(uint32_t uid)
{
    static std::unordered_map<uint32_t, std::string> cache;
    auto it = cache.find(uid);
    if (it != cache.end()) return it->second.c_str();

    char buf[256];
    struct passwd pw, *result = nullptr;
    if (getpwuid_r(uid, &pw, buf, sizeof(buf), &result) == 0 && result)
        cache[uid] = result->pw_name;
    else
        cache[uid] = std::to_string(uid);
    return cache[uid].c_str();
}
```

**출력 변화:**

```
# 변경 전
[EXEC ]  1234.567s  PID=1234  PPID=1  UID=33    php-fpm         /usr/sbin/php-fpm8.1

# 변경 후
[EXEC ]  1234.567s  PID=1234  PPID=1  www-data    php-fpm         /usr/sbin/php-fpm8.1
```

---

### 2.7 IPv4-mapped IPv6 주소 정규화

`connect(AF_INET6)` 소켓이 IPv4 주소에 연결할 때 커널이 자동으로 `::ffff:1.2.3.4` 형태로 변환한다. `inet_ntop(AF_INET6, ...)` 결과가 `::ffff:` 접두사를 포함하면 이를 제거하여 순수 IPv4 주소로 표시한다.

```cpp
const char *ip_display = ip;
if (strncmp(ip, "::ffff:", 7) == 0)
    ip_display = ip + 7;
```

---

### 2.8 세션 통계 출력

Ctrl+C 종료 시 세션 동안의 이벤트 처리 결과를 요약한다.

```
=== 세션 통계 ===
총 이벤트: 1523  (EXEC=312  FILE=891  NET=320)

룰          발화 횟수
----------------------------
R-007        8 회
R-005        5 회
R-006        3 회
R-011        1 회
```

통계는 dedup 이후 실제 출력된 알림만 카운트하여 실질적인 탐지 빈도를 나타낸다.

---

## 3. 변경된 파일 구조

```
edr-agent/
├── include/
│   └── common.h               # exit_event 구조체, EVENT_PROC_EXIT 상수 추가
├── bpf/
│   ├── process_monitor.bpf.c  # rb_exit 맵, sched_process_exit 훅 추가
│   └── network_monitor.bpf.c  # pending_connect 맵, sys_exit_connect 훅 추가
│                                 parse_and_submit → fill_net_event + stage 분리
└── src/
    ├── main.cpp               # dedup, uid_name, 통계, IPv6 정규화, graceful drain
    └── output/
        └── http_reporter.cpp  # 헤더 인젝션 방지: token CR/LF 제거
```

---

## 4. 탐지 룰 전체 목록 (3주차 기준)

| ID | 이름 | 이벤트 | 심각도 | 추가 시점 |
|---|---|---|---|---|
| R-001 | 시스템 경로 파일 수정 | FILE_WRITE | high | 1주차 |
| R-002 | 로그 파일 삭제 | FILE_DELETE | high | 1주차 |
| R-003 | `/tmp` 경로 실행 (드로퍼) | PROC_EXEC | high | 1주차 |
| R-004 | 리버스셸/스캔 도구 실행 | PROC_EXEC | critical | 1주차 |
| R-005 | 스크립트 인터프리터 실행 | PROC_EXEC | medium | 1주차 |
| R-006 | 비표준 포트 아웃바운드 | NET_CONNECT | medium | 1주차 |
| R-007 | 서버 포트 바인드 (미지 프로세스) | NET_BIND | low | 1주차 |
| R-008 | root 권한 인터프리터 실행 | PROC_EXEC | critical | 1주차 |
| R-009 | `/tmp` → 시스템 경로 rename | FILE_RENAME | critical | 1주차 |
| R-010 | 인터프리터 `-c`/`-e` 인라인 페이로드 | PROC_EXEC | high | 2주차 |
| R-011 | 웹 서버 자식 셸 실행 (웹셸) | PROC_EXEC | critical | 2주차 |
| R-012 | DB 서버 자식 셸 실행 (SQLi RCE) | PROC_EXEC | critical | 2주차 |

---

## 5. 기술적 고찰

### 5.1 sys_exit_connect 에서 EINPROGRESS 처리

`connect()` 시스템 콜의 반환값은 블로킹/논블로킹 소켓에 따라 다르다.

| 소켓 타입 | 반환값 | 의미 |
|---|---|---|
| 블로킹 TCP | 0 | 3-way handshake 완료 |
| 논블로킹 TCP | -EINPROGRESS(-115) | SYN 전송됨, 연결 진행 중 |
| UDP | 0 | 기본 주소 설정 (패킷 전송 없음) |
| 실패 | -ECONNREFUSED 등 | 연결 거절/오류 |

EINPROGRESS를 "성공"으로 처리하는 것은 보안 관점에서 중요하다. 역방향 셸이나 C2 클라이언트는 논블로킹 소켓을 이용해 빠른 연결 시도를 반복하는 경우가 많기 때문이다.

### 5.2 dedup 윈도우 설정의 트레이드오프

dedup 윈도우를 너무 짧게 설정하면 빠른 공격 반복을 놓치고, 너무 길게 설정하면 정당한 탐지가 억제된다. 3초는 다음 기준으로 선택하였다:
- nginx 시작 시 포트 바인드 연속(보통 1초 내) → 억제 가능
- 공격자가 1분 간격으로 반복 시도하는 시나리오 → 탐지 가능
- 운영자가 출력을 확인할 수 있는 최소 간격

### 5.3 BPF 링버퍼 분리의 의미

`rb` (프로세스/파일/네트워크 이벤트)와 `rb_exit` (종료 이벤트)를 분리한 이유:
- 종료 이벤트는 크기가 작고(~30 bytes) 빈도가 높다. 같은 버퍼를 공유하면 대형 `process_event`(~560 bytes)가 버퍼를 빠르게 채울 때 종료 이벤트가 드롭될 수 있다.
- 유저스페이스에서 `ring_buffer__add()`로 두 링버퍼를 동일한 epoll 인스턴스에 등록하여 단일 폴 루프로 처리한다.

---

## 6. 다음 주 계획

| 항목 | 내용 |
|---|---|
| 백엔드 API 연동 테스트 | 백엔드 팀 수신 서버 엔드포인트 연결 확인 |
| 팀 통합 발표 준비 | 에이전트 파트 데모 시나리오 구성 |

---

*소스코드: https://github.com/no-carve-only-pizza/edr-agent*
