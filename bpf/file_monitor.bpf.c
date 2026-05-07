// SPDX-License-Identifier: GPL-2.0
/*
 * file_monitor.bpf.c - EDR Agent: 파일시스템 변경 감시 BPF 커널 프로그램
 *
 * ┌─ 감시 대상 syscall 과 커널 경로 ──────────────────────────────────────┐
 * │                                                                        │
 * │  write/create:                                                         │
 * │    openat(dirfd, path, O_WRONLY|O_CREAT|...)                          │
 * │      → syscall 진입점 → sys_enter_openat 트레이스포인트 ★            │
 * │      → do_sys_openat2() → vfs_open() → 실제 파일 열림                │
 * │                                                                        │
 * │  delete:                                                               │
 * │    unlink(path) / unlinkat(dirfd, path, flags)                        │
 * │      → sys_enter_unlinkat 트레이스포인트 ★                           │
 * │      → do_unlinkat() → vfs_unlink() → 디렉터리 엔트리 제거           │
 * │                                                                        │
 * │  rename:                                                               │
 * │    rename/renameat/renameat2(old, new, flags)                         │
 * │      → sys_enter_renameat2 트레이스포인트 ★                          │
 * │      → do_renameat2() → vfs_rename() → 디렉터리 엔트리 이동          │
 * │                                                                        │
 * │  ★ 표시: BPF 프로그램이 부착되는 훅 포인트                           │
 * │                                                                        │
 * │  sys_enter_* vs sys_exit_*:                                           │
 * │    sys_enter 는 syscall 진입 시 발화 (성공 여부 미정).                │
 * │    sys_exit  는 syscall 반환 시 발화 (반환값으로 성공 여부 판별 가능).│
 * │    EDR 탐지 목적으로는 "시도" 자체를 기록하는 sys_enter 를 사용.     │
 * │    EPERM/ENOENT 등 실패 케이스까지 잡으려면 sys_exit 를 추가할 것.   │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * 경로 획득 방식:
 *   sys_enter 시점의 인자는 유저스페이스 포인터(user VA).
 *   bpf_probe_read_user_str() 로 BPF 힙(링버퍼 슬롯)에 복사한다.
 *   커널 내부의 struct file / struct dentry 에서 절대 경로를 재구성하려면
 *   sys_exit 훅 + fd-to-path 변환이 필요하다 (마일스톤 3 이후 과제).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/*
 * O_* 플래그 상수: uapi/asm-generic/fcntl.h 정의값.
 * vmlinux.h 에는 uapi 상수가 포함되지 않으므로 직접 정의한다.
 *
 * x86_64 기준 (아키텍처별로 일부 차이 있음):
 *   O_RDONLY = 0x000   O_WRONLY = 0x001   O_RDWR   = 0x002
 *   O_CREAT  = 0x040   O_TRUNC  = 0x200   O_APPEND = 0x400
 */
#define O_WRONLY  0x001
#define O_RDWR    0x002
#define O_CREAT   0x040
#define O_TRUNC   0x200

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} rb SEC(".maps");

/* ── 공통 헬퍼: 이벤트 헤더 채우기 ────────────────────────────────────── */

/*
 * fill_header():
 *   모든 이벤트 타입에서 공통으로 채우는 필드를 한 곳에서 처리.
 *   __always_inline: BPF verifier 스택 프레임 제한(512B) 때문에
 *   함수 호출을 인라인으로 전개하도록 강제한다.
 */
static __always_inline void fill_header(struct file_event *e,
                                         __u32 type, __u32 flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->type  = type;
    e->pid   = (__u32)(pid_tgid >> 32);  /* TGID → 유저스페이스 PID */
    e->uid   = (__u32)bpf_get_current_uid_gid();
    e->flags = flags;
    e->ts_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ── [1] openat: 파일 쓰기/생성 감지 ───────────────────────────────────
 *
 * sys_enter_openat 트레이스포인트 인자 (ctx->args[]):
 *   [0] = dfd      : 기준 디렉터리 fd (AT_FDCWD=-100 이면 cwd 기준)
 *   [1] = filename : 파일 경로 (userspace ptr)
 *   [2] = flags    : O_RDONLY / O_WRONLY / O_CREAT / ...
 *   [3] = mode     : 파일 생성 시 권한 비트 (O_CREAT 시에만 유효)
 *
 * 필터링 전략:
 *   O_RDONLY(=0) 전용 open 은 무시. 쓰기 의도(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)
 *   가 있는 경우만 이벤트를 기록한다. → 읽기 전용 파일 접근의 노이즈 제거.
 */
SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 flags = (__u32)ctx->args[2];

    /* 읽기 전용 open 은 EDR 파일 감시 대상 아님 */
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(e, EVENT_FILE_WRITE, flags);
    e->path2[0] = '\0';  /* 미사용 필드 명시적 초기화 */

    /*
     * bpf_probe_read_user_str():
     *   ctx->args[1] 은 유저스페이스의 char* 포인터.
     *   "user" 변형을 사용해야 하는 이유:
     *     커널 메모리(kernel VA): bpf_probe_read_kernel_str()
     *     유저 메모리(user VA):   bpf_probe_read_user_str()
     *   잘못된 변형을 사용하면 SMEP/SMAP 으로 인해 폴트가 발생한다.
     *
     *   반환값: 복사된 바이트 수(NUL 포함). 접근 불가 시 음수.
     */
    bpf_probe_read_user_str(&e->path, sizeof(e->path),
                             (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── [2] unlinkat: 파일 삭제 감지 ──────────────────────────────────────
 *
 * unlink(path) 는 내부적으로 unlinkat(AT_FDCWD, path, 0) 로 변환된다.
 * rmdir(path) 는 unlinkat(AT_FDCWD, path, AT_REMOVEDIR) 로 변환된다.
 *
 * sys_enter_unlinkat 인자:
 *   [0] = dfd      : 기준 디렉터리 fd
 *   [1] = pathname : 삭제할 경로 (userspace ptr)
 *   [2] = flag     : 0 또는 AT_REMOVEDIR(0x200)
 *
 * 커널 동작:
 *   do_unlinkat() → security_inode_unlink() [LSM 검사]
 *                 → vfs_unlink() → inode.i_op->unlink()
 *                 → dentry 의 d_inode 링크 해제
 *                 → 마지막 참조가 사라지면 실제 inode 해제 (GC)
 */
SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(e, EVENT_FILE_DELETE, (__u32)ctx->args[2]);
    e->path2[0] = '\0';

    bpf_probe_read_user_str(&e->path, sizeof(e->path),
                             (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── [3] renameat2: 파일/디렉터리 이름 변경 감지 ────────────────────────
 *
 * rename(old, new) → renameat(AT_FDCWD, old, AT_FDCWD, new)
 *                  → renameat2(AT_FDCWD, old, AT_FDCWD, new, 0)
 *
 * sys_enter_renameat2 인자:
 *   [0] = olddirfd : 원본 기준 fd
 *   [1] = oldpath  : 원본 경로 (userspace ptr)
 *   [2] = newdirfd : 대상 기준 fd
 *   [3] = newpath  : 대상 경로 (userspace ptr)
 *   [4] = flags    : RENAME_NOREPLACE(1), RENAME_EXCHANGE(2), ...
 *
 * 보안 관점:
 *   rename() 은 원자적(atomic)이다 → TOCTOU 공격의 핵심 수단.
 *   예: /tmp/evil → /etc/cron.d/backdoor 같은 권한 상승 이동을 탐지.
 *   path(원본) + path2(대상) 쌍을 모두 기록해야 탐지 가능하다.
 */
SEC("tp/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(e, EVENT_FILE_RENAME, (__u32)ctx->args[4]);

    /* oldpath → e->path, newpath → e->path2 */
    bpf_probe_read_user_str(&e->path,  sizeof(e->path),
                             (const char *)ctx->args[1]);
    bpf_probe_read_user_str(&e->path2, sizeof(e->path2),
                             (const char *)ctx->args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
