# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-08  
**작성자:** (본인 이름)

---

## 1. 개요

4주차에는 기존 1~3주차에서 완성한 파일, 네트워크, 프로세스 기반 이벤트 수집에 더해 **메모리 기반 위협 탐지 기능(R-016)**을 추가로 구현하였다. 또한 BPF 프로그램의 복잡도가 증가함에 따라 발생한 **BPF Verifier(검증기) 오류를 커널 레벨에서 우회 및 해결**하는 안정화 작업을 수행하였다. 

1. **메모리 할당 이벤트 훅**: `mmap`, `mprotect` 시스템 콜 모니터링
2. **RWX 메모리 탐지 (R-016)**: JIT 스프레이 및 쉘코드 인젝션 방어
3. **BPF Verifier 한계 극복**: BPF 스택 크기 제한 및 `variable-offset write` 검증 오류 해결
4. **JSON 직렬화 및 룰 엔진 통합**: 메모리 이벤트 구조체 통합 및 출력 연동

---

## 2. 구현 내용

### 2.1 파일리스(Fileless) 공격 방어: RWX 메모리 할당 감지 (R-016)

#### 2.1.1 문제
최신 악성코드(루트킷, 드로퍼 등)는 디스크에 악성 페이로드를 쓰지 않고 메모리 공간을 할당받아 직접 쉘코드를 삽입한 뒤 실행하는 파일리스 기법을 자주 사용한다. 이를 위해 메모리 페이지에 읽기(Read), 쓰기(Write), 실행(Execute) 권한이 동시에 필요하다.

#### 2.1.2 구현
`sys_enter_mmap` 및 `sys_enter_mprotect` 트레이스포인트를 후킹하여 프로세스가 요청하는 메모리 보호 권한(`prot`)을 검사한다.
`PROT_EXEC(4)`와 `PROT_WRITE(2)` 권한이 비트 마스킹으로 동시에 설정되는 경우 이벤트를 캡처하여 유저스페이스로 전송한다.

```c
// memory_monitor.bpf.c 발췌
#define PROT_WRITE_EXEC 6 // PROT_EXEC(4) | PROT_WRITE(2)

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long prot = ctx->args[2];
    
    if ((prot & PROT_WRITE_EXEC) == PROT_WRITE_EXEC) {
        struct memory_event *e = bpf_ringbuf_reserve(&rb_mem, sizeof(*e), 0);
        // ... (PID, UID, comm 수집 후 전송)
    }
    return 0;
}
```

유저스페이스의 룰 엔진(`rule_engine.cpp`)에서는 해당 이벤트를 받아 `R-016 (RWX 메모리 할당)` 룰로 판정하여 High 등급의 알림을 발생시킨다. C++ 전용 테스트 프로그램(`test_mmap.c`)을 작성하여 `mmap`과 `mprotect` 호출 시 실시간으로 탐지 및 알림이 중복 억제(dedup)되어 출력됨을 성공적으로 검증하였다.

---

### 2.2 BPF Verifier(검증기) 한계 극복 및 구조 최적화

기존 `process_monitor.bpf.c` 내 프로세스 실행 인자(`argv`)를 파싱하는 로직에서 BPF 커널 로드 시 두 가지 치명적인 검증기 에러가 발생하였다.

#### 2.2.1 BPF 스택 한계 초과 에러 해결
*   **원인**: BPF 프로그램은 커널 안전성을 위해 스택 크기가 512바이트로 엄격히 제한된다. 256바이트 이상의 `argv_cache_t` 구조체를 BPF 스택 로컬 변수로 선언하고 처리하려다 보니 스택 초과 및 `uninitialized read` 검증 오류(`Permission denied`)가 발생했다.
*   **해결**: 로컬 스택 변수를 사용하는 대신, `BPF_MAP_TYPE_HASH` 타입의 eBPF 맵(`argv_store`)을 임시 저장소로 활용하도록 아키텍처를 변경했다. 포인터를 꺼내 힙 메모리처럼 접근함으로써 스택 크기 제한을 우회했다.

```c
// 스택 대신 Map Value 사용
struct argv_cache_t zero = {};
bpf_map_update_elem(&argv_store, &pid, &zero, BPF_ANY);
struct argv_cache_t *entry = bpf_map_lookup_elem(&argv_store, &pid);
if (!entry) return 0;
```

#### 2.2.2 Variable-Offset Write(가변 길이 메모리 접근) 오류 해결
*   **원인**: `bpf_probe_read_user_str` 함수로 가변 길이의 유저 문자열(`argv`)을 버퍼에 복사할 때, 복사 길이나 시작 위치(`off`)가 컴파일 타임에 확정되지 않는 경우, 검증기가 메모리 경계 밖 쓰기 위험이 있다고 판단하여 프로그램 로드를 거부하였다 (`invalid access to map value / invalid variable-offset write`).
*   **해결**: 컴파일러와 검증기에게 명확한 상한선(Upper Bound)을 알려주기 위해 비트 연산(`AND 마스크`)을 통한 힌트(Hinting)를 삽입하였다.

```c
__u32 mask_off = off & (MAX_ARGV_LEN - 1);
__u32 len = MAX_ARGV_LEN - mask_off;
if (len > MAX_ARGV_LEN) len = MAX_ARGV_LEN; // Verifier Hint 1
len &= (MAX_ARGV_LEN - 1);                  // Verifier Hint 2

int r = bpf_probe_read_user_str(entry->buf + mask_off, len, arg);
```
이러한 조치를 통해 최신 리눅스 커널의 엄격해진 eBPF 메모리 검증을 성공적으로 우회하고 안정적으로 모니터링 데몬이 실행되도록 보완하였다.

---

### 2.3 eBPF 맵 가비지 컬렉션(Map Garbage Collection) 도입

eBPF 프로그램의 장기 실행 시 발생할 수 있는 커널 메모리 누수(Memory Leak)를 방지하기 위해 맵 정리 로직을 고도화하였다.

#### 2.3.1 `argv_store` 클린업
*   **문제**: `sys_enter_execve` 훅에서 인자들을 임시 맵(`argv_store`)에 저장하고, `sched_process_exec` 훅에서 소비 후 삭제한다. 하지만 권한 부족(`EACCES`)이나 파일 없음(`ENOENT`) 등으로 `execve` 시스템 콜이 실패하면 `sched_process_exec`가 호출되지 않아 맵에 찌꺼기 데이터가 영구히 남는 문제가 있었다.
*   **해결**: `sys_exit_execve` 트레이스포인트를 추가로 후킹하여, 반환값(`ctx->ret`)이 음수(실패)인 경우 `argv_store`에서 해당 PID의 데이터를 강제로 삭제하도록 구현하였다.

#### 2.3.2 `pending_connect` 스레드 레벨 클린업
*   **문제**: 네트워크 연결 시 `sys_enter_connect`에서 `pending_connect` 맵에 TID(스레드 ID) 단위로 데이터를 보관한다. 만약 연결 도중 스레드가 강제 종료되거나 타임아웃 처리가 불완전하게 이루어지면 데이터가 남게 된다.
*   **해결**: `network_monitor.bpf.c` 내에 `sched_process_exit` 훅을 추가로 도입하여 스레드가 종료될 때 무조건 `pending_connect` 맵에서 해당 TID의 엔트리를 삭제하도록 안전장치(Fallback GC)를 마련하였다.

이로써 에이전트를 수개월간 가동하더라도 커널 메모리 고갈(OOM)이나 해시맵 가득 참(Map Full) 에러 없이 안정적으로 동작하는 상용 EDR 수준의 내구성을 확보하였다.

---

## 3. 다음 목표 (Next Steps)

현재 에이전트 측의 주요 데이터 수집 및 룰 매칭 로직은 완성 단계이다. 차주부터는 다음과 같은 작업을 중심으로 연동 및 고도화를 진행할 계획이다.

1. **백엔드 연동 테스트**: 백엔드 팀의 HTTP 수신 서버 엔드포인트가 준비되는 대로, `--endpoint` 플래그를 통한 NDJSON 배치 전송 및 Bearer 토큰 인증 로직 통합 테스트 진행.
2. **시연 데모 시나리오 구축**: R-001 ~ R-016 룰이 효과적으로 동작함을 시각적으로 보여주기 위해, `메모리 쉘코드 인젝션`, `LD_PRELOAD 가로채기`, `비표준 포트 백도어 생성` 등의 모의 해킹 시나리오 스크립트화.
3. **추가 안정화 (선택)**: 런타임 동적 설정(JSON) 로드 도입 및 `memfd_create` 모니터링을 통한 파일리스 탐지 정교화 검토.