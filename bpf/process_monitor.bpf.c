// SPDX-License-Identifier: GPL-2.0
/*
 * process_monitor.bpf.c - EDR Agent: 프로세스 실행 감시 BPF 커널 프로그램
 *
 * ┌─ 커널 실행 흐름 ──────────────────────────────────────────────────────┐
 * │  유저: execve("/bin/ls", ...)                                         │
 * │    │                                                                   │
 * │    ▼ sys_call_table[__NR_execve]                                       │
 * │  syscall 진입점 (arch/x86/entry/entry_64.S: entry_SYSCALL_64)         │
 * │    │  → CPU가 ring3 → ring0 전환, RSP를 커널 스택으로 교체             │
 * │    ▼                                                                   │
 * │  do_execve() → do_execveat_common()                                   │
 * │    │  → bprm 구조체 초기화, 바이너리 로더(ELF) 호출                   │
 * │    │  → 기존 VAS(Virtual Address Space) 해제, 새 매핑 생성            │
 * │    ▼  [성공 시에만]                                                    │
 * │  trace_sched_process_exec()  ← ★ 이 BPF 프로그램이 여기 걸린다        │
 * │    │  → 링버퍼에 이벤트 기록                                           │
 * │    ▼                                                                   │
 * │  새 프로세스 진입점(entry point)으로 점프                              │
 * └───────────────────────────────────────────────────────────────────────┘
 *
 * execve() 실패(ENOENT, EACCES 등)에서는 트레이스포인트가 발화하지 않으므로
 * false-positive 없이 "실제로 실행된" 프로세스만 캡처된다.
 */

/*
 * vmlinux.h: BTF(BPF Type Format) 정보를 기반으로 bpftool이 생성하는 헤더.
 * 커널의 모든 타입 정의를 담고 있어 개별 kernel 헤더를 include할 필요가 없다.
 * CO-RE(Compile Once, Run Everywhere)의 핵심: 타입 정보가 BPF 오브젝트 내
 * .BTF 섹션에 임베드되어, 런타임에 실제 커널 필드 오프셋으로 재배치된다.
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>   /* BPF helper 함수 선언 (bpf_get_current_pid_tgid 등) */
#include <bpf/bpf_tracing.h>   /* SEC() 매크로, 트레이스포인트 관련 정의              */
#include <bpf/bpf_core_read.h> /* BPF_CORE_READ() - CO-RE 안전 메모리 접근 매크로   */

#include "common.h"

/*
 * BPF Map: BPF_MAP_TYPE_RINGBUF
 *
 * 커널 5.8+에서 도입된 lock-free 단방향 큐. 기존 perf_event_output 대비:
 *   - Zero-copy: 커널이 슬롯에 직접 쓰고, 유저는 그 메모리를 mmap으로 읽음
 *   - 이벤트 순서 보장 (per-CPU 버퍼인 perf buffer는 CPU 간 순서 비보장)
 *   - 메모리 절약: 슬롯 크기가 가변 (perf buffer는 고정 크기 페이지 낭비)
 *
 * SEC(".maps"): BPF 오브젝트의 .maps ELF 섹션에 배치.
 *              libbpf가 이 섹션을 파싱해 bpf_map_create() 시스템 콜을 호출한다.
 *
 * max_entries: 링버퍼 크기 (바이트). 반드시 2의 거듭제곱 & PAGE_SIZE의 배수.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} rb SEC(".maps");

/* 프로세스 종료 이벤트 전용 링버퍼. exit_event 크기가 작으므로 256 KiB 충분. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KiB */
} rb_exit SEC(".maps");

/* ptrace 이벤트 전용 링버퍼. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KiB */
} rb_ptrace SEC(".maps");

/*
 * argv_store: sys_enter_execve → sched_process_exec 데이터 전달 채널.
 *
 * 두 훅이 왜 분리되어 있는가:
 *   - sys_enter_execve: argv 포인터 배열이 아직 유저 스택에 있어 읽기 가능.
 *     그러나 execve() 가 성공한다는 보장이 없다 (ENOENT, EACCES 등).
 *   - sched_process_exec: execve() 성공이 보장되고 경로가 커널에 의해 해석된다.
 *     그러나 이 시점에서는 이미 원본 argv 를 읽을 수 없다.
 *
 * 따라서 PID 를 키로 두 훅 사이에 임시 버퍼를 공유한다.
 *
 * 생명주기:
 *   insert: sys_enter_execve (execve 시도 시)
 *   delete: sched_process_exec (execve 성공 시, 이벤트에 복사 후 삭제)
 *   누락:   execve 실패 시 엔트리가 남지만, 같은 PID 의 다음 execve 가 덮어쓴다.
 */

/* BPF 내부 전용 - argv 임시 저장소 값 타입 (common.h 에는 노출 불필요) */
struct argv_cache_t {
    char  buf[MAX_ARGV_LEN]; /* NUL 구분 argv 연결: /proc/PID/cmdline 형식 */
    __u32 argc;              /* 실제 저장된 인자 수                         */
    __u8  has_ld_preload;    /* 1 if envp 에 LD_PRELOAD= 포함               */
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096); /* 동시 최대 execve 진행 수 (PID 수 기준) */
    __type(key,   __u32);      /* PID (유저스페이스 기준 TGID)            */
    __type(value, struct argv_cache_t);
} argv_store SEC(".maps");

/*
 * SEC("tp/sched/sched_process_exec")
 *
 * 트레이스포인트 명명 규칙: "tp/<category>/<name>"
 *   - category: /sys/kernel/debug/tracing/events/ 하위 디렉토리
 *   - name:     해당 디렉토리 내 이벤트 이름
 *
 * sched_process_exec의 발화 위치:
 *   kernel/sched/core.c: sched_exec() 내부가 아니라,
 *   fs/exec.c: exec_binprm() 성공 직후 → trace_sched_process_exec() 호출
 *
 * 컨텍스트: 새 프로세스를 exec한 태스크의 커널 스택에서 실행.
 *           인터럽트 비활성화 구간이 아니므로 preemption 가능.
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *e;
    struct task_struct   *task;
    __u64  pid_tgid;
    __u64  uid_gid;
    __u32  fname_off;

    /* ── 1. 링버퍼 슬롯 예약 ─────────────────────────────────────────────
     *
     * BPF 프로그램의 스택 한계는 512 바이트.
     * struct process_event 크기(약 556B)를 스택에 놓으면 한계를 초과하므로
     * 링버퍼에서 메모리를 빌리는 것이 필수다.
     *
     * bpf_ringbuf_reserve()는 원자적 포인터 이동(xadd)으로 O(1) 확보.
     * 버퍼가 가득 찬 경우 NULL을 반환 → 이벤트 드롭 (손실 허용 설계).
     */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* ── 2. PID / PPID 획득 ──────────────────────────────────────────────
     *
     * 리눅스 커널 내부 용어 vs 유저스페이스 용어의 역전:
     *
     *   커널 task_struct.pid  = 유저스페이스 gettid()  (개별 스레드 ID)
     *   커널 task_struct.tgid = 유저스페이스 getpid()  (프로세스 그룹 리더 ID)
     *
     * bpf_get_current_pid_tgid() 반환값 (u64):
     *   [63:32] = tgid  (유저스페이스의 PID)
     *   [31: 0] = pid   (유저스페이스의 TID)
     */
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid   = (__u32)(pid_tgid >> 32);  /* TGID → 유저스페이스 PID */

    /*
     * 부모 PID: task_struct.real_parent.tgid
     *
     * BPF_CORE_READ(task, real_parent, tgid):
     *   CO-RE 매크로. 컴파일 시 타입 정보를 .BTF 섹션에 기록하고,
     *   커널 로드 시 실제 tgid 필드 오프셋을 계산해 bpf_probe_read_kernel()
     *   로 안전하게 읽는다. 커널 버전별 구조체 레이아웃 변화에 자동 대응.
     *
     * real_parent vs parent:
     *   real_parent = 실제 fork()한 부모 (SIGCHLD 수신자)
     *   parent      = ptrace 중이면 ptracer를 가리킬 수 있음
     */
    task    = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /*
     * euid: R-015 setuid 바이너리 실행 탐지용.
     * exec() 성공 후 cred->euid 가 이미 새 바이너리의 소유자 UID로 변경된다.
     * uid(real) ≠ euid(effective) → setuid 실행.
     */
    {
        const struct cred *cred = BPF_CORE_READ(task, cred);
        e->euid = BPF_CORE_READ(cred, euid.val);
    }

    /* ── 3. UID 획득 ─────────────────────────────────────────────────────
     *
     * bpf_get_current_uid_gid() 반환값 (u64):
     *   [63:32] = GID
     *   [31: 0] = UID (effective user id)
     */
    uid_gid = bpf_get_current_uid_gid();
    e->uid  = (__u32)uid_gid;

    /* ── 4. 타임스탬프 ───────────────────────────────────────────────────
     *
     * bpf_ktime_get_ns(): CLOCK_MONOTONIC 기반, 시스템 부팅 이후 나노초.
     * 절대 시각(epoch)이 아닌 상대 시각임에 주의.
     * 유저스페이스에서 clock_gettime(CLOCK_BOOTTIME)과 동기화 가능.
     */
    e->ts_ns = bpf_ktime_get_ns();

    /* ── 5. 프로세스 이름 (comm) ─────────────────────────────────────────
     *
     * bpf_get_current_comm()은 현재 task_struct.comm을 복사한다.
     * comm = 실행 파일의 basename, 최대 15글자 + NUL.
     * exec() 호출 시 커널이 load_elf_binary() 내부에서 set_task_comm()으로 갱신.
     */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* ── 6. 실행 파일 경로 (filename) ────────────────────────────────────
     *
     * 트레이스포인트 구조체의 __data_loc 인코딩:
     *
     *   trace_event_raw_sched_process_exec.__data_loc_filename 는 u32로,
     *   실제 문자열 데이터의 위치를 인코딩한다:
     *
     *     bits [31:16] = 데이터 길이 (bytes)
     *     bits [15: 0] = ctx 구조체 시작으로부터의 오프셋 (bytes)
     *
     *   실제 문자열 위치 = (char *)ctx + (ctx->__data_loc_filename & 0xFFFF)
     *
     * 이 인코딩은 가변 길이 데이터를 고정 크기 구조체 뒤에 이어 붙이는
     * 커널 트레이스 이벤트의 표준 패턴이다.
     *
     * bpf_probe_read_kernel_str():
     *   커널 주소 공간에서 NUL 종단까지 안전하게 복사.
     *   반환값: 복사된 바이트 수 (NUL 포함). 실패 시 음수.
     */
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                               (void *)ctx + fname_off);

    /* ── 7. argv 병합: sys_enter_execve 에서 미리 저장한 데이터 소비 ────
     *
     * 흐름: sys_enter_execve → argv_store[pid] 저장 → (exec 성공 시)
     *       sched_process_exec → argv_store[pid] 조회·복사 → 맵에서 삭제.
     *
     * bpf_map_lookup_elem(): 성공 시 맵 값에 대한 직접 포인터 반환.
     *   반환된 포인터는 커널 메모리를 직접 가리키므로
     *   bpf_probe_read_kernel 없이 __builtin_memcpy 로 읽을 수 있다.
     *
     * 맵 조회 실패(execveat 경유, 경쟁 조건 등): e->argc = 0 으로 미캡처 표시.
     */
    {
        __u32 pid_key = e->pid;
        struct argv_cache_t *av = bpf_map_lookup_elem(&argv_store, &pid_key);
        if (av) {
            __builtin_memcpy(e->argv, av->buf, MAX_ARGV_LEN);
            e->argc           = av->argc;
            e->has_ld_preload = av->has_ld_preload;
            bpf_map_delete_elem(&argv_store, &pid_key);
        } else {
            e->argc           = 0;
            e->has_ld_preload = 0;
        }
    }

    /* ── 8. 링버퍼 제출 ──────────────────────────────────────────────────
     *
     * bpf_ringbuf_submit()은 슬롯의 헤더 비트를 "소비 가능" 상태로 원자적으로
     * 갱신(cmpxchg)한다. 유저스페이스의 ring_buffer__poll()이 epoll_wait()로
     * 깨어나 handle_event() 콜백을 실행하게 된다.
     *
     * 주의: submit() 이후에는 e 포인터로 접근하면 안 된다 (UAF).
     *       discard()를 사용하면 이벤트를 취소할 수 있다.
     */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * sys_enter_execve: execve() syscall 진입 시 argv[] 를 미리 캡처.
 *
 * ┌─ 왜 sys_enter_execve 인가 ───────────────────────────────────────────┐
 * │  execve() 진입 시점(ring3→ring0 전환 직후):                         │
 * │    - argv 포인터 배열이 아직 유저 스택/힙에 있어 읽기 가능           │
 * │    - do_execveat_common() 이 bprm→argv 를 커널로 복사하기 전        │
 * │                                                                       │
 * │  sched_process_exec 시점:                                            │
 * │    - 새 VAS 매핑 완료, 원본 유저 스택은 이미 교체됨                  │
 * │    - argv 를 읽을 방법이 없음 → 두 훅을 조합해야 한다               │
 * └───────────────────────────────────────────────────────────────────────┘
 *
 * 트레이스포인트 컨텍스트 (trace_event_raw_sys_enter):
 *   ctx->args[0] = filename  (const char __user *)
 *   ctx->args[1] = argv      (const char __user * const __user *)
 *   ctx->args[2] = envp      (const char __user * const __user *)
 *
 * BPF 스택 사용량 추정 (~292 B < 512 B):
 *   struct argv_cache_t entry: 260 B
 *   지역 변수 (pid, argv_user, off, arg, r): ~32 B
 */
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32         pid      = (__u32)(bpf_get_current_pid_tgid() >> 32);
    const char  **argv_user = (const char **)ctx->args[1];

    /*
     * argv_cache_t 를 BPF 스택에 선언.
     * = {} 로 제로 초기화: BPF 검증기가 "uninitialized read" 를 감지하지 않도록.
     */
    struct argv_cache_t entry = {};
    __u32 off = 0;

    /*
     * #pragma unroll: 컴파일러가 루프를 MAX_ARGC 번 완전 전개(unroll).
     *
     * BPF 검증기는 루프 반복 횟수가 정적으로 결정된 경우에만 분석 가능하다.
     * Linux 5.3+ 에서는 bounded loop 도 지원하지만, unroll 이 더 안전하다.
     * (검증기가 각 반복의 레지스터 범위를 독립적으로 추적)
     *
     * 각 반복에서:
     *   1. argv_user[i] (유저 포인터) 읽기 → bpf_probe_read_user()
     *      NULL = argv 배열 끝 → break
     *   2. 유저 문자열 읽기 → bpf_probe_read_user_str()
     *      반환값 r: 복사된 바이트 수 (NUL 포함). 실패 = 음수.
     *   3. off 증가 및 경계 검사
     */
    #pragma unroll
    for (int i = 0; i < MAX_ARGC; i++) {
        const char *arg = NULL;

        /* argv[i] 포인터 자체를 유저 메모리에서 읽음 */
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv_user[i]) < 0 || !arg)
            break;

        /*
         * 버퍼 경계 체크: off 가 MAX_ARGV_LEN - 1 이상이면 공간 없음.
         *
         * (off & (MAX_ARGV_LEN - 1)) 패턴:
         *   MAX_ARGV_LEN = 256 = 2^8 이므로, AND 마스크로 [0, 255] 범위를 강제.
         *   BPF 검증기가 배열 오프셋의 상한(upper bound)을 추적할 때
         *   이 마스크가 없으면 "R1 min value is negative" 등의 오류 발생 가능.
         */
        if (off >= MAX_ARGV_LEN - 1)
            break;

        int r = bpf_probe_read_user_str(
            entry.buf + (off & (MAX_ARGV_LEN - 1)),
            MAX_ARGV_LEN - (off & (MAX_ARGV_LEN - 1)),
            arg);

        if (r < 0)
            break;

        entry.argc++;
        off += (__u32)r; /* r에는 NUL 바이트 포함 → 다음 인자 시작 위치 */
    }

    /*
     * envp 스캔: LD_PRELOAD= 탐지 (R-013).
     *
     * LD_PRELOAD 는 공유 라이브러리 인젝션의 전형적 기법이다.
     *   - 공격자: LD_PRELOAD=/tmp/evil.so ls  → evil.so 의 심볼이 우선 로드
     *   - 루트킷: LD_PRELOAD 로 libc 함수 후킹(readdir, open 등 은폐)
     *
     * 처음 16개 환경변수만 검사한다:
     *   LD_PRELOAD 는 보통 첫 몇 개 env 에 위치한다.
     *   16회 #pragma unroll → BPF 검증기 복잡도 제한 내.
     *
     * envbuf[12]: "LD_PRELOAD=" = 11자 + NUL. 값 내용은 불필요.
     */
    {
        const char **envp_user = (const char **)ctx->args[2];
        char envbuf[12] = {};
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            const char *env = NULL;
            if (bpf_probe_read_user(&env, sizeof(env), &envp_user[i]) < 0 || !env)
                break;
            bpf_probe_read_user_str(envbuf, sizeof(envbuf), env);
            /* "LD_PRELOAD=" 11자 직접 비교 (strncmp 불가 - BPF 스택 경계 문제) */
            if (envbuf[0]=='L' && envbuf[1]=='D' && envbuf[2]=='_' &&
                envbuf[3]=='P' && envbuf[4]=='R' && envbuf[5]=='E' &&
                envbuf[6]=='L' && envbuf[7]=='O' && envbuf[8]=='A' &&
                envbuf[9]=='D' && envbuf[10]=='=') {
                entry.has_ld_preload = 1;
            }
        }
    }

    /* PID 를 키로 argv_store 에 저장. sched_process_exec 에서 소비. */
    bpf_map_update_elem(&argv_store, &pid, &entry, BPF_ANY);
    return 0;
}

/*
 * BPF 라이선스 선언: GPL 호환 라이선스가 선언된 프로그램만
 * bpf_probe_read_kernel() 등 "GPL only" helper를 사용할 수 있다.
 * 커널이 bpf(BPF_PROG_LOAD) 시 이 필드를 검사한다.
 */
/*
 * sys_enter_ptrace: ptrace() ATTACH 감지 (R-014).
 *
 * ptrace 는 리눅스 프로세스 디버깅/추적 인터페이스로, 다음 공격에 악용된다:
 *   - 프로세스 인젝션: PTRACE_ATTACH → PTRACE_POKEDATA 로 실행 중인 프로세스
 *     메모리에 쉘코드 삽입 후 실행 (고전적 userland rootkit 기법)
 *   - 자격증명 탈취: PTRACE_ATTACH → ssh/sshd 메모리에서 비밀번호 읽기
 *   - 안티-포렌식: ptrace 로 다른 프로세스의 행위를 조작
 *
 * sys_enter_ptrace 인자:
 *   args[0] = request  (PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206, ...)
 *   args[1] = pid      (대상 프로세스 PID)
 *   args[2] = addr
 *   args[3] = data
 *
 * PTRACE_ATTACH 와 PTRACE_SEIZE 만 캡처한다.
 * PTRACE_POKEDATA 등 은 ATTACH 없이는 실패하므로 ATTACH 탐지로 충분하다.
 */
#define PTRACE_ATTACH 16
#define PTRACE_SEIZE  0x4206

SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 request = (__u32)ctx->args[0];

    if (request != PTRACE_ATTACH && request != PTRACE_SEIZE)
        return 0;

    struct ptrace_event *e = bpf_ringbuf_reserve(&rb_ptrace, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid        = (__u32)(pid_tgid >> 32);
    e->target_pid = (__u32)ctx->args[1];
    e->uid        = (__u32)bpf_get_current_uid_gid();
    e->request    = request;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * sched_process_exit: 프로세스 종료 시 ProcTree 정리를 위한 훅.
 *
 * 유저스페이스의 g_proc_tree 는 exec 이벤트로만 채워지므로,
 * 종료된 PID 를 명시적으로 알려주지 않으면 메모리가 계속 증가한다.
 *
 * 스레드 필터링:
 *   스레드 종료 시에도 이 훅이 발화하므로, TID != TGID 인 경우를 걸러낸다.
 *   커널 내부: task_struct.pid (TID) vs task_struct.tgid (TGID/PID)
 *   bpf_get_current_pid_tgid(): [63:32]=TGID, [31:0]=TID
 *
 * exit_code: task_struct.exit_code
 *   정상 종료: (exit_code >> 8) & 0xFF = 종료 코드
 *   시그널:    exit_code & 0x7F = 시그널 번호
 */
SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)pid_tgid;

    /* 스레드 종료는 무시 - 프로세스 리더(메인 스레드)만 처리 */
    if (tgid != tid)
        return 0;

    struct exit_event *e = bpf_ringbuf_reserve(&rb_exit, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid       = tgid;
    e->ts_ns     = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = BPF_CORE_READ(task, exit_code);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
