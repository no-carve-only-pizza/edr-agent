// SPDX-License-Identifier: GPL-2.0
/*
 * network_monitor.bpf.c - EDR Agent: 네트워크 연결 감시 BPF 커널 프로그램
 *
 * ┌─ connect() 의 커널 경로 ────────────────────────────────────────────────┐
 * │                                                                          │
 * │  유저: connect(sockfd, &addr, addrlen)                                  │
 * │    │                                                                     │
 * │    ▼ sys_call_table[__NR_connect]                                        │
 * │  entry_SYSCALL_64 (ring3 → ring0, RSP 교체)                            │
 * │    │                                                                     │
 * │    ▼ sys_enter_connect 트레이스포인트 ★ BPF 훅                         │
 * │    │   → 이 시점에 BPF가 sockaddr를 유저스페이스 메모리에서 읽는다      │
 * │    │                                                                     │
 * │    ▼ __sys_connect() → __sys_connect_file()                             │
 * │    │   → sock->ops->connect() (프로토콜별 구현)                         │
 * │    │                                                                     │
 * │    │  [TCP 경우]                                                         │
 * │    │   → tcp_v4_connect()                                                │
 * │    │     → ip_route_connect() (라우팅 테이블 조회)                      │
 * │    │     → tcp_connect() (SYN 패킷 생성 및 전송)                        │
 * │    │     → 3-way handshake 완료 대기 (블로킹 소켓의 경우)               │
 * │    │                                                                     │
 * │    │  [UDP 경우]                                                         │
 * │    │   → udp_v4_connect() (실제 패킷 없이 default dst 주소만 설정)      │
 * │    │                                                                     │
 * │    ▼ 반환 (성공: 0, 실패: -ECONNREFUSED 등)                             │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ bind() 의 커널 경로 ───────────────────────────────────────────────────┐
 * │                                                                          │
 * │  유저: bind(sockfd, &addr, addrlen)                                     │
 * │    │                                                                     │
 * │    ▼ sys_enter_bind 트레이스포인트 ★ BPF 훅                            │
 * │    │                                                                     │
 * │    ▼ __sys_bind() → sock->ops->bind()                                   │
 * │    │   → inet_bind() → sk_set_port()                                    │
 * │    │   → 포트 가용성 검사 (bind_conflict)                                │
 * │    │   → 포트 예약 (소켓에 포트 번호 할당)                               │
 * │    │                                                                     │
 * │  이후 listen(sockfd, backlog) 를 호출해야 실제 서버 소켓이 된다.        │
 * │  bind() 단계에서 감지하면 "서버를 열려는 의도"를 더 일찍 탐지 가능.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * sys_enter_* 를 사용하는 이유:
 *   - 현재 프로세스 컨텍스트에서 실행 → bpf_get_current_pid_tgid() 정확
 *   - 네트워크 이벤트 중 많은 수는 softirq/kworker 에서 완료되어
 *     sys_exit 훅에서도 PID를 얻기 어렵다
 *   - "시도" 자체를 탐지하는 것이 EDR에서는 오히려 더 유용
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/*
 * AF_* 상수: uapi/linux/socket.h 정의.
 * vmlinux.h 는 커널 내부 타입만 포함하므로 uapi 상수는 직접 정의.
 */
#define AF_INET   2
#define AF_INET6  10

/*
 * sockaddr 관련 구조체 수동 정의.
 * vmlinux.h 의 struct sockaddr_in 은 커널 내부 필드명을 가지며
 * bpf_probe_read_user 로 유저스페이스 메모리를 읽을 때 레이아웃만 맞으면 된다.
 *
 * struct sockaddr_in 레이아웃 (POSIX, x86_64):
 *   offset 0: sa_family_t sin_family  (2 bytes)
 *   offset 2: in_port_t   sin_port    (2 bytes, big-endian)
 *   offset 4: struct in_addr sin_addr (4 bytes)
 *   offset 8: char         sin_zero[8] (padding)
 *
 * struct sockaddr_in6 레이아웃:
 *   offset 0:  sa_family_t sin6_family   (2 bytes)
 *   offset 2:  in_port_t   sin6_port     (2 bytes, big-endian)
 *   offset 4:  uint32_t    sin6_flowinfo (4 bytes)
 *   offset 8:  struct in6_addr sin6_addr (16 bytes)
 *   offset 24: uint32_t    sin6_scope_id (4 bytes)
 */
struct edr_sockaddr_in {
    __u16 family;
    __u16 port;      /* big-endian */
    __u8  addr[4];   /* IPv4 주소 */
};

struct edr_sockaddr_in6 {
    __u16 family;
    __u16 port;      /* big-endian */
    __u32 flowinfo;
    __u8  addr[16];  /* IPv6 주소 */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} rb SEC(".maps");

/*
 * pending_connect: sys_enter_connect → sys_exit_connect 데이터 전달 채널.
 *
 * connect()의 sockaddr 는 sys_enter 시점에만 유효하다.
 * sys_exit 에서 성공 여부를 확인한 뒤 링버퍼에 제출하기 위해
 * TID 를 키로 net_event 를 임시 보관한다.
 *
 * TID(스레드 ID)로 키잉하는 이유:
 *   멀티스레드 프로세스에서 두 스레드가 동시에 connect() 하는 경우
 *   PID(TGID)로 키잉하면 덮어쓰기가 발생한다.
 *   TID = bpf_get_current_pid_tgid() 하위 32비트.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);           /* TID */
    __type(value, struct net_event);
} pending_connect SEC(".maps");

/* ── 공통 헬퍼: sockaddr 파싱 ───────────────────────────────────────────── */

/*
 * fill_net_event(): sockaddr 유저 포인터를 읽어 net_event 를 채운다.
 * 반환값: 0 = 성공, -1 = 실패(비IP 소켓 또는 읽기 오류).
 *
 * bpf_probe_read_user():
 *   SMAP(Supervisor Mode Access Prevention) 우회를 BPF 런타임이 처리.
 */
static __always_inline int fill_net_event(struct net_event *e,
                                           __u32 type,
                                           const void *uaddr)
{
    __u16 family;
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return -1;
    if (family != AF_INET && family != AF_INET6)
        return -1; /* AF_UNIX, AF_NETLINK 등 비IP 소켓 제외 */

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type   = type;
    e->pid    = (__u32)(pid_tgid >> 32);
    e->uid    = (__u32)bpf_get_current_uid_gid();
    e->family = family;
    e->ts_ns  = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (family == AF_INET) {
        struct edr_sockaddr_in sa4;
        if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr) < 0) return -1;
        e->dport = sa4.port;
        __builtin_memcpy(e->daddr, sa4.addr, 4);
        __builtin_memset(e->daddr + 4, 0, 12);
    } else {
        struct edr_sockaddr_in6 sa6;
        if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) < 0) return -1;
        e->dport = sa6.port;
        __builtin_memcpy(e->daddr, sa6.addr, 16);
    }
    return 0;
}

/* bind 은 성공 여부 확인 없이 바로 제출 (기존 동작 유지) */
static __always_inline int parse_and_submit(__u32 type, const void *uaddr)
{
    struct net_event *slot = bpf_ringbuf_reserve(&rb, sizeof(*slot), 0);
    if (!slot) return 0;
    if (fill_net_event(slot, type, uaddr) < 0) {
        bpf_ringbuf_discard(slot, 0);
        return 0;
    }
    bpf_ringbuf_submit(slot, 0);
    return 0;
}

/* ── [1] connect(): 아웃바운드 연결 ─────────────────────────────────────────
 *
 * 두 훅 패턴으로 "성공한 연결"만 캡처한다.
 *
 *   sys_enter_connect: sockaddr 정보가 유효한 시점. pending_connect 에 보관.
 *   sys_exit_connect:  반환값 확인.
 *     ret == 0           : 즉시 성공 (UDP, 로컬 소켓)
 *     ret == -EINPROGRESS: 논블로킹 TCP (SYN 전송됨, 연결 진행 중)
 *     그 외              : 실패 (ECONNREFUSED, ETIMEDOUT 등) → 드롭
 *
 * EINPROGRESS(-115) 를 "성공"으로 취급하는 이유:
 *   논블로킹 소켓은 connect() 가 즉시 -EINPROGRESS 를 반환하고
 *   이후 poll/epoll 로 완료를 기다린다. 공격자가 사용하는 역방향 셸,
 *   포트 스캐너 등은 대부분 논블로킹 소켓을 사용하므로 이를 포함해야 한다.
 */
#define EINPROGRESS 115

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct net_event e = {};
    if (fill_net_event(&e, EVENT_NET_CONNECT, (const void *)ctx->args[1]) < 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_connect, &tid, &e, BPF_ANY);
    return 0;
}

/*
 * sys_exit_connect: connect() 반환 시점에 성공 여부 확인 후 링버퍼 제출.
 *
 * ctx->ret: 커널이 sys_connect() 에서 반환하는 값 (long).
 *   유저스페이스에는 음수 errno 로 변환되지만 BPF 에서는 음수 값 그대로.
 *
 * ts_ns 갱신: 연결 완료(또는 SYN 전송) 시각이 더 정확하므로 덮어쓴다.
 */
SEC("tp/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct net_event *pending = bpf_map_lookup_elem(&pending_connect, &tid);
    if (!pending) return 0;

    long ret = ctx->ret;
    if (ret != 0 && ret != -(long)EINPROGRESS) {
        bpf_map_delete_elem(&pending_connect, &tid);
        return 0;
    }

    struct net_event *slot = bpf_ringbuf_reserve(&rb, sizeof(*slot), 0);
    if (slot) {
        __builtin_memcpy(slot, pending, sizeof(*slot));
        slot->ts_ns = bpf_ktime_get_ns(); /* 연결 완료 시각으로 갱신 */
        bpf_ringbuf_submit(slot, 0);
    }
    bpf_map_delete_elem(&pending_connect, &tid);
    return 0;
}

/* ── [2] bind(): 서버 소켓 오픈 감지 ────────────────────────────────────────
 *
 * sys_enter_bind 인자:
 *   args[0] = sockfd
 *   args[1] = umyaddr : 바인드할 로컬 주소 (유저스페이스 포인터)
 *   args[2] = addrlen
 *
 * bind() 이후 listen() 을 호출해야 서버 소켓이 완성되지만,
 * bind() 시점에 감지하면 "서버를 열려는 의도"를 더 일찍 탐지할 수 있다.
 *
 * 보안 관점:
 *   예상치 못한 포트에서의 bind 는 백도어/RAT 의 전형적 지표.
 *   특히 UID=0 이 아닌 프로세스가 1024 미만 포트에 bind 하는 경우.
 *   (정상적이라면 CAP_NET_BIND_SERVICE 없이 불가하므로 실패하지만 시도 자체 탐지)
 */
SEC("tp/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx)
{
    return parse_and_submit(EVENT_NET_BIND, (const void *)ctx->args[1]);
}

char LICENSE[] SEC("license") = "GPL";
