# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-08  
**작성자:** (본인 이름)

---

## 1. 개요

6주차에는 컨테이너 환경에 특화된 **탈출 시도 탐지 기능(R-024)**과, 재컴파일 없이 탐지 룰을 수정할 수 있는 **YAML 룰 외부화 아키텍처**를 구현하였다.

1. **컨테이너 탈출 감지 (R-024)**: `unshare()` 훅 + CO-RE 기반 PID 네임스페이스 inum 비교
2. **YAML 룰 외부화**: `RuleConfig` 구조체 + YAML 서브셋 파서 + `init_rules()` API

---

## 2. 구현 내용

### 2.1 컨테이너 탈출 탐지 (R-024)

#### 2.1.1 공격 원리

컨테이너(Docker, Kubernetes 등)는 리눅스 네임스페이스로 격리된다. 공격자가 컨테이너 내부에서 `unshare(CLONE_NEWUSER | CLONE_NEWNS)` 를 호출하면:

```
컨테이너 내부
  └─ unshare(CLONE_NEWUSER)   ← 새 사용자 네임스페이스에서 UID=0 (root) 획득
       └─ mount --bind / /mnt ← 호스트 루트 파일시스템 마운트
            └─ chroot /mnt    ← 호스트로 탈출
```

CVE-2019-5736(runc 탈출), CVE-2022-0492(cgroup release_agent) 등이 이 패턴을 활용한다.

#### 2.1.2 PID 네임스페이스 inum 비교

컨테이너인지 판단하는 방법: 현재 프로세스의 PID 네임스페이스 inode 번호와 init 프로세스(PID 1)의 PID 네임스페이스 inode 번호를 비교한다.

```
호스트:     /proc/1/ns/pid  →  inode=4026531836  (init ns)
컨테이너:   /proc/1/ns/pid  →  inode=4026532217  (격리된 ns)
            현재 프로세스   →  inode=4026532217  ← init와 다름 → in_container=1
```

유저스페이스는 에이전트 시작 시 `stat("/proc/1/ns/pid")` 로 inode 번호를 읽어 BPF 배열 맵(`init_pid_ns_inum`)에 기록한다. BPF 훅은 CO-RE(Compile Once Run Everywhere)로 현재 프로세스의 PID 네임스페이스 inum을 커널 구조체에서 직접 읽는다.

```c
// ns_monitor.bpf.c 발췌

/*
 * CO-RE: task->nsproxy->pid_ns_for_children->ns.inum
 * BTF 타입 정보로 런타임 커널 오프셋을 자동 조정하므로
 * 커널 버전이 달라져도 재컴파일 없이 동작한다.
 */
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
__u64 cur_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

__u32 key = 0;
__u64 *init_inum_ptr = bpf_map_lookup_elem(&init_pid_ns_inum, &key);
__u8 in_container = 0;
if (init_inum_ptr && *init_inum_ptr != 0 && cur_inum != *init_inum_ptr)
    in_container = 1;
```

#### 2.1.3 탐지 룰 (R-024)

| 조건 | 심각도 | 설명 |
|---|---|---|
| `in_container=1` + `CLONE_NEWUSER` | **critical** | 컨테이너 내 user ns 분리 → root 권한 획득 시도 |
| `in_container=1` + NS 플래그 2개 이상 | **high** | 복수 ns 동시 분리 → 탈출 준비 |
| `CLONE_NEWUSER` + `CLONE_NEWNS` 또는 `CLONE_NEWPID` | **medium** | 호스트에서도 의심스러운 권한 상승 패턴 |

`newuidmap`, `newgidmap`, `unshare`(유틸리티), `systemd-nspawn`, `bwrap`(Flatpak), `lxc-*`, `podman`, `docker` 등 합법적으로 네임스페이스를 분리하는 프로세스는 화이트리스트로 제외한다.

#### 2.1.4 출력 예시

```
[UNSHR]  5432.100s  PID=1234    root          evil              ns=[user mnt]  [IN CONTAINER]
  >>> [ALERT] R-024 | 컨테이너 탈출 시도: 컨테이너 내 사용자 네임스페이스 분리
[CORRL]  ...         상관 패턴 탐지 (R-019: ptrace + memfd)
```

---

### 2.2 YAML 룰 외부화

#### 2.2.1 문제: 하드코딩된 룰의 한계

기존 코드는 화이트리스트, 블랙리스트, 포트 목록이 모두 `rule_engine.cpp` 내 `static const char*[]` 배열로 하드코딩되어 있었다. 새 프로세스를 화이트리스트에 추가하거나 포트를 변경하려면 재컴파일이 필요했다.

#### 2.2.2 아키텍처 설계

```
config/rules.yaml
      │
      ▼ RuleConfig::load() ← YAML 서브셋 파서 (stdlib만 사용, 외부 의존성 없음)
      │
      ▼ RuleConfig 구조체 (std::vector<std::string> × 18 + std::vector<uint16_t> × 1)
      │
      ▼ init_rules(cfg) → rule_engine.cpp 내 static 벡터 초기화
      │
      ▼ match_rules(event) → 탐지 로직 (변경 없음)
```

`nlohmann/json`, `yaml-cpp` 등 외부 라이브러리 없이 stdlib만으로 구현하였다. 지원하는 YAML 서브셋:

```yaml
# 주석
section_name:         # 섹션 헤더 (콜론으로 끝나는 줄)
  - value             # 목록 항목
```

이 정도면 룰 설정 파일로 충분하며, 전체 YAML 스펙(앵커, 멀티라인 등)을 지원할 이유가 없다.

#### 2.2.3 파서 구현

```cpp
bool RuleConfig::load(const std::string &path)
{
    std::ifstream f(path);
    if (!f.is_open()) return false;

    // 파일을 열었으면 기존 내용을 모두 클리어하고 YAML로 완전 교체
    sensitive_paths.clear();  // ... 전체 클리어 ...

    std::vector<std::string> *cur_str = nullptr;
    bool cur_port = false;

    std::string line;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        if (t.size() >= 2 && t[0] == '-' && t[1] == ' ') {
            // 목록 항목: "- value"
            std::string val = trim(t.substr(2));
            if (cur_port) {
                uint16_t p = (uint16_t)std::strtoul(val.c_str(), nullptr, 10);
                if (p) common_ports.push_back(p);
            } else if (cur_str) {
                cur_str->push_back(val);
            }
        } else if (!t.empty() && t.back() == ':') {
            // 섹션 헤더: "key:"
            std::string key = t.substr(0, t.size() - 1);
            cur_port = (key == "common_ports");
            auto it = str_map.find(key);
            cur_str = (it != str_map.end()) ? it->second : nullptr;
        }
    }
    return true;
}
```

#### 2.2.4 rule_engine.cpp 리팩터링

`static const char *LIST[] = {..., nullptr}` 패턴을 모두 `static std::vector<std::string> LIST` 로 변환하고, 헬퍼 함수 시그니처를 벡터 참조로 변경하였다.

```cpp
// 변경 전
static bool comm_in(const char *comm, const char * const *list) { ... }

// 변경 후
static bool comm_in(const char *comm, const std::vector<std::string> &list) { ... }
```

#### 2.2.5 사용 방법

```bash
# 기본값 사용 (재컴파일 없이 즉시 실행)
sudo ./build/edr-agent

# YAML 룰 파일 지정
sudo ./build/edr-agent --rules config/rules.yaml

# 운영 환경에 맞게 rules.yaml 수정 후 재시작만으로 룰 갱신
vim config/rules.yaml
sudo systemctl restart edr-agent
```

파일 열기에 실패하면 내장 기본값으로 자동 폴백하므로 설정 파일이 없어도 에이전트는 정상 동작한다.

---

## 3. 최종 아키텍처

현재까지 구현된 전체 파이프라인:

```
BPF 커널 프로그램 (6개 파일)          유저스페이스
─────────────────────────────────────────────────────────────────
process_monitor.bpf.c                  RuleConfig::load_defaults()
  sched_process_exec  ─┐               RuleConfig::load(rules.yaml)  ← --rules
  sched_process_exit   │                      │
  sys_enter_execve     │                 init_rules(cfg)
                        │
file_monitor.bpf.c      │  ring_buffer   match_rules()      stdout (table)
  sys_enter_openat    ──┤  (mmap)    ─▶  dedup_alerts()  ─▶ NDJSON 파일
  sys_enter_unlinkat  ──┤              to_json()            HTTP POST
  sys_enter_renameat2 ──┤                    │
                        │              CorrelationEngine    ← [CORRL] 상관 패턴
network_monitor.bpf.c   │              .feed(pid, evt, ts)
  sys_enter_connect   ──┤
  sys_exit_connect    ──┤
  sys_enter_bind      ──┤

memory_monitor.bpf.c    │
  sys_enter_mmap      ──┤
  sys_enter_mprotect  ──┤
  sys_enter_memfd     ──┤

dns_monitor.bpf.c       │
  sys_enter_sendto    ──┤  (DNS 포트 53 필터 + QNAME 파싱 in BPF)

ns_monitor.bpf.c        │
  sys_enter_unshare   ──┘  (PID ns inum 비교 → in_container)
```

## 4. 탐지 룰 전체 목록 (R-001 ~ R-024)

| ID | 이름 | 심각도 | 탐지 방식 |
|---|---|---|---|
| R-001 | 시스템 경로 파일 수정 | high | 단일 이벤트 |
| R-002 | 로그 파일 삭제 | high | 단일 이벤트 |
| R-003 | /tmp 경로 실행 | high | 단일 이벤트 |
| R-004 | 리버스셸/스캔 도구 실행 | critical | 단일 이벤트 |
| R-005 | 스크립트 인터프리터 실행 | medium | 단일 이벤트 |
| R-006 | 비표준 포트 아웃바운드 연결 | medium | 단일 이벤트 |
| R-007 | 미지 프로세스 서버 바인드 | low | 단일 이벤트 |
| R-008 | root 권한 인터프리터 실행 | critical | 단일 이벤트 |
| R-009 | /tmp→시스템경로 rename (TOCTOU) | critical | 단일 이벤트 |
| R-010 | 인터프리터 -c/-e 인라인 페이로드 | high | 단일 이벤트 |
| R-011 | 웹 서버 자식 셸 실행 (웹셸) | critical | 프로세스 트리 |
| R-012 | DB 서버 자식 셸 실행 (SQLi RCE) | critical | 프로세스 트리 |
| R-013 | LD_PRELOAD 환경변수 인젝션 | high | 단일 이벤트 |
| R-014 | ptrace ATTACH 인젝션 의심 | high | 단일 이벤트 |
| R-015 | 예상치 못한 setuid 실행 | critical | 단일 이벤트 |
| R-016 | RWX 메모리 할당 (JIT/셸코드) | high | 단일 이벤트 |
| R-017 | memfd_create 파일리스 공격 | critical/high | 단일 이벤트 |
| R-018a | DNS 터널링 (레이블 > 50자) | critical | 단일 이벤트 |
| R-018b | DGA 도메인 의심 (랜덤 서브도메인) | high | 단일 이벤트 |
| R-018c | 남용 TLD 접속 (.tk/.ml/.ga 등) | medium | 단일 이벤트 |
| R-019 | 프로세스 인젝션 체인 (ptrace+memfd) | critical | 상관 분석 |
| R-020 | 드로퍼 C2 체인 (/tmp실행+연결) | critical | 상관 분석 |
| R-021 | 다운로드+실행 (/tmp쓰기+실행) | critical | 상관 분석 |
| R-022 | 파일리스 C2 (RWX메모리+연결) | critical | 상관 분석 |
| R-023 | C2 비콘 (의심DNS+연결) | high | 상관 분석 |
| R-024 | 컨테이너 탈출 시도 (ns unshare) | critical/high | 단일 이벤트 |

## 5. 남은 과제

- **백엔드 연동 검증**: `--endpoint`를 통한 NDJSON 배치 전송 실 환경 테스트
- **데모 시나리오 실행**: `demo/run_demo.sh` 스크립트로 R-001~R-024 전체 룰 발화 시연
- **성능 측정**: 고부하 환경(웹 서버 트래픽)에서 ring_buffer 손실률(dropped events) 측정
