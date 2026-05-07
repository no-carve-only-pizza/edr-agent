
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

// PROT_EXEC = 4, PROT_WRITE = 2
#define PROT_WRITE_EXEC 6 

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} rb_mem SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    // mmap(addr, length, prot, flags, fd, offset)
    // args[2] is prot
    unsigned long prot = ctx->args[2];
    
    if ((prot & PROT_WRITE_EXEC) == PROT_WRITE_EXEC) {
        struct memory_event *e;
        e = bpf_ringbuf_reserve(&rb_mem, sizeof(*e), 0);
        if (!e) return 0;

        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid();
        e->ts_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        
        e->prot = prot;
        e->is_mprotect = 0;

        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tracepoint__syscalls__sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    // mprotect(addr, len, prot)
    // args[2] is prot
    unsigned long prot = ctx->args[2];

    if ((prot & PROT_WRITE_EXEC) == PROT_WRITE_EXEC) {
        struct memory_event *e;
        e = bpf_ringbuf_reserve(&rb_mem, sizeof(*e), 0);
        if (!e) return 0;

        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid();
        e->ts_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        
        e->prot = prot;
        e->is_mprotect = 1;

        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
