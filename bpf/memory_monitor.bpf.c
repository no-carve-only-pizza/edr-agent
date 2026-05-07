// SPDX-License-Identifier: GPL-2.0
/*
 * memory_monitor.bpf.c - EDR Agent: RWX 메모리 할당 감시 BPF 커널 프로그램
 *
 * ┌─ 탐지 원리 ─────────────────────────────────────────────────────────────┐
 * │                                                                          │
 * │  정상적인 코드: 쓰기(W)와 실행(X) 권한을 동시에 갖는 메모리 페이지는   │
 * │  거의 존재하지 않는다. W^X(Write XOR eXecute) 원칙이 현대 OS의 기본.  │
 * │                                                                          │
 * │  공격자 관점: 셸코드·JIT 페이로드 인젝션의 전형적 패턴:                │
 * │    1. mmap(NULL, size, PROT_WRITE|PROT_EXEC, MAP_ANON, -1, 0)           │
 * │       → 쓰기+실행 가능한 익명 메모리 할당                               │
 * │    2. memcpy(addr, shellcode, len)                                       │
 * │       → 셸코드 복사                                                      │
 * │    3. ((void(*)())addr)()                                                │
 * │       → 셸코드 실행                                                      │
 * │                                                                          │
 * │  또는 mprotect() 를 이용한 2단계 패턴:                                  │
 * │    1. mmap(PROT_WRITE)   → 쓰기 전용으로 먼저 할당                      │
 * │    2. memcpy(셸코드)     → 내용 작성                                    │
 * │    3. mprotect(PROT_EXEC) → 실행 권한 추가 (W|X 순간 발생)              │
 * │                                                                          │
 * │  훅 위치: sys_enter_mmap, sys_enter_mprotect                            │
 * │    - syscall 진입 시점이므로 현재 프로세스 컨텍스트에서 실행            │
 * │    - prot 인자가 유저스페이스 레지스터에 있어 ctx->args[] 로 직접 접근  │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/*
 * PROT_* 상수: uapi/linux/mman.h 정의.
 * vmlinux.h 는 커널 내부 타입만 포함하므로 uapi 상수는 직접 정의.
 *
 *   PROT_READ  = 1  (읽기)
 *   PROT_WRITE = 2  (쓰기)
 *   PROT_EXEC  = 4  (실행)
 *
 * PROT_WRITE|PROT_EXEC = 6: 쓰기+실행 동시 보유 → W^X 위반 → 탐지 대상.
 */
#define PROT_WRITE_EXEC 6

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KiB */
} rb_mem SEC(".maps");

/*
 * fill_memory_event(): 공통 필드 채우기 헬퍼.
 *
 * mmap 과 mprotect 훅 모두 동일한 필드를 채우므로 공통화.
 * is_mprotect: 0 = mmap, 1 = mprotect (유저스페이스 JSON "type" 필드 구분용).
 */
static __always_inline void fill_memory_event(struct memory_event *e,
                                               unsigned long prot,
                                               __u32 is_mprotect)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid         = (__u32)(pid_tgid >> 32);
    e->uid         = (__u32)bpf_get_current_uid_gid();
    e->ts_ns       = bpf_ktime_get_ns();
    e->prot        = (__u32)prot;
    e->is_mprotect = is_mprotect;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ── [1] mmap(): 쓰기+실행 익명 메모리 할당 감지 ───────────────────────────
 *
 * sys_enter_mmap 인자 (x86_64 mmap2 syscall):
 *   args[0] = addr    (힌트 주소, 보통 NULL)
 *   args[1] = length  (요청 크기)
 *   args[2] = prot    (PROT_READ | PROT_WRITE | PROT_EXEC 조합)
 *   args[3] = flags   (MAP_SHARED | MAP_PRIVATE | MAP_ANON 등)
 *   args[4] = fd      (MAP_ANON 이면 -1)
 *   args[5] = offset
 *
 * 탐지 조건: prot & (PROT_WRITE|PROT_EXEC) == (PROT_WRITE|PROT_EXEC)
 *   단순 PROT_EXEC 만인 경우(읽기+실행, 정상 코드 매핑)는 제외.
 */
SEC("tp/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long prot = (unsigned long)ctx->args[2];

    if ((prot & PROT_WRITE_EXEC) != PROT_WRITE_EXEC)
        return 0;

    struct memory_event *e = bpf_ringbuf_reserve(&rb_mem, sizeof(*e), 0);
    if (!e) return 0;

    fill_memory_event(e, prot, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── [2] mprotect(): 기존 매핑에 실행 권한 추가 감지 ───────────────────────
 *
 * sys_enter_mprotect 인자:
 *   args[0] = addr    (변경할 메모리 시작 주소, 페이지 정렬)
 *   args[1] = len     (변경할 크기)
 *   args[2] = prot    (새 권한 플래그)
 *
 * mmap(PROT_WRITE) → memcpy(셸코드) → mprotect(PROT_EXEC) 패턴:
 *   mmap 단계에서 W|X 가 동시에 나타나지 않을 수 있으므로
 *   mprotect 훅이 이 2단계 패턴을 보완적으로 탐지한다.
 *
 * 단, mprotect(PROT_READ|PROT_EXEC) 은 정상(공유 라이브러리 보호 강화) 이고
 * mprotect(PROT_WRITE|PROT_EXEC) 만 비정상이므로 동일한 조건으로 필터링.
 */
SEC("tp/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long prot = (unsigned long)ctx->args[2];

    if ((prot & PROT_WRITE_EXEC) != PROT_WRITE_EXEC)
        return 0;

    struct memory_event *e = bpf_ringbuf_reserve(&rb_mem, sizeof(*e), 0);
    if (!e) return 0;

    fill_memory_event(e, prot, 1);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── [3] memfd_create(): 파일리스 공격 익명 메모리 파일 감지 ────────────────
 *
 * sys_enter_memfd_create 인자:
 *   args[0] = name   (const char __user *): 사람이 읽는 레이블, 경로 아님
 *   args[1] = flags  (unsigned int):
 *               MFD_CLOEXEC     = 0x0001 (exec 시 fd 자동 닫기)
 *               MFD_ALLOW_SEALING = 0x0002 (fcntl F_ADD_SEALS 허용)
 *
 * 파일리스 공격 패턴:
 *   memfd_create("", MFD_CLOEXEC) → fd
 *   write(fd, shellcode, len)      → 메모리에 셸코드 기록
 *   fexecve(fd, argv, envp)        → 디스크 흔적 없이 실행
 *
 * R-016(mmap RWX) 과 달리 memfd 는 JIT 런타임(Java, V8)이 아닌
 * 셸코드 드로퍼에서 주로 사용한다. 유저스페이스에서 별도 화이트리스트로 FP 억제.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KiB */
} rb_memfd SEC(".maps");

SEC("tp/syscalls/sys_enter_memfd_create")
int handle_memfd(struct trace_event_raw_sys_enter *ctx)
{
    struct memfd_event *e = bpf_ringbuf_reserve(&rb_memfd, sizeof(*e), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid   = (__u32)(pid_tgid >> 32);
    e->uid   = (__u32)bpf_get_current_uid_gid();
    e->flags = (__u32)ctx->args[1];
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /*
     * name 인자를 유저스페이스에서 읽는다.
     * 빈 문자열("") 또는 수상한 이름이면 유저스페이스 룰에서 판단.
     */
    const char *uname = (const char *)ctx->args[0];
    if (uname)
        bpf_probe_read_user_str(e->name, sizeof(e->name), uname);
    else
        e->name[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
