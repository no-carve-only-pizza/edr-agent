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
     * struct process_event 크기(약 296B)를 스택에 놓으면 한계에 근접하므로
     * 링버퍼에서 메모리를 빌리는 것이 안전하다.
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

    /* ── 3. UID 획득 ─────────────────────────────────────────────────────
     *
     * bpf_get_current_uid_gid() 반환값 (u64):
     *   [63:32] = GID
     *   [31: 0] = UID (effective user id)
     */
    uid_gid = bpf_get_current_uid_gid();
    e->uid  = (__u32)uid_gid;

    e->_pad = 0;

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

    /* ── 7. 링버퍼 제출 ──────────────────────────────────────────────────
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
 * BPF 라이선스 선언: GPL 호환 라이선스가 선언된 프로그램만
 * bpf_probe_read_kernel() 등 "GPL only" helper를 사용할 수 있다.
 * 커널이 bpf(BPF_PROG_LOAD) 시 이 필드를 검사한다.
 */
char LICENSE[] SEC("license") = "GPL";
