// SPDX-License-Identifier: GPL-2.0
/*
 * ns_monitor.bpf.c - 네임스페이스 분리 감지 (컨테이너 탈출 탐지)
 *
 * ┌─ 탐지 대상 ─────────────────────────────────────────────────────────────┐
 * │                                                                          │
 * │  sys_enter_unshare                                                       │
 * │    → CLONE_NEW* 플래그 포함 시 캡처                                     │
 * │    → 현재 PID 네임스페이스 inum 을 init PID 네임스페이스 inum 과 비교   │
 * │    → 불일치(= 컨테이너 내부) 이면 in_container=1 로 표시               │
 * │                                                                          │
 * │  탐지 룰:                                                                │
 * │    R-024: 컨테이너 탈출 시도 — 컨테이너 내에서 user/pid/mount ns 분리  │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * CO-RE 사용:
 *   BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum)
 *   vmlinux.h 의 타입 정보로 런타임 커널 오프셋을 자동 조정한다.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/*
 * CLONE_NEW* 플래그 상수.
 * vmlinux.h 에 이미 정의된 경우 재정의를 피하기 위해 #ifndef 사용.
 */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS    0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC    0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER   0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID    0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET    0x40000000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

/* 네임스페이스 관련 플래그 전체 마스크 */
#define NS_FLAGS_MASK (CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID | \
                       CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | \
                       CLONE_NEWCGROUP)

/* ── BPF 맵 ─────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb_ns SEC(".maps");

/*
 * init_pid_ns_inum: 유저스페이스가 시작 시 /proc/1/ns/pid 의 inode 번호를 기록.
 * key=0 에 단일 __u64 를 저장하는 1원소 배열 맵.
 *
 * 값이 0 이면 "아직 초기화되지 않음" 으로 간주하여 in_container 비교를 건너뜀.
 * 유저스페이스가 stat("/proc/1/ns/pid", &st) → st.st_ino 로 채운다.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} init_pid_ns_inum SEC(".maps");

/* ── 훅: sys_enter_unshare ───────────────────────────────────────────────── */

SEC("tp/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx)
{
    __u32 flags = (__u32)ctx->args[0];

    /* 네임스페이스와 무관한 unshare() (예: CLONE_FILES, CLONE_FS) 는 무시 */
    if (!(flags & NS_FLAGS_MASK)) return 0;

    /*
     * 현재 PID 네임스페이스 inum 읽기 (CO-RE).
     *
     * task->nsproxy->pid_ns_for_children->ns.inum 경로:
     *   nsproxy: 네임스페이스 포인터 모음 구조체
     *   pid_ns_for_children: 이 프로세스의 자식이 태어날 PID 네임스페이스
     *   ns.inum: 네임스페이스 파일의 inode 번호 (proc 파일시스템에 노출)
     *
     * "for_children" 을 사용하는 이유: unshare() 는 자신의 네임스페이스를
     * 분리하므로, 호출 시점에 "자신이 속한" 네임스페이스가 곧 변경 대상이다.
     */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 cur_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    /*
     * init PID 네임스페이스 inum 과 비교.
     * cur_inum != init_inum → 현재 프로세스가 컨테이너(또는 서브 네임스페이스) 내부.
     */
    __u32 key = 0;
    __u64 *init_inum_ptr = bpf_map_lookup_elem(&init_pid_ns_inum, &key);
    __u8 in_container = 0;
    if (init_inum_ptr && *init_inum_ptr != 0 && cur_inum != *init_inum_ptr)
        in_container = 1;

    struct ns_event *e = bpf_ringbuf_reserve(&rb_ns, sizeof(*e), 0);
    if (!e) return 0;

    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->ts_ns        = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->flags        = flags;
    e->in_container = in_container;
    e->_pad[0]      = 0;
    e->_pad[1]      = 0;
    e->_pad[2]      = 0;
    e->ns_inum      = cur_inum;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
