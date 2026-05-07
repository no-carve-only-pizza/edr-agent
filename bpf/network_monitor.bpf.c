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

/* ── 공통 헬퍼: sockaddr 파싱 + 이벤트 채우기 ──────────────────────────── */

/*
 * parse_and_submit():
 *   유저스페이스의 struct sockaddr * 를 읽어 net_event 를 링버퍼에 제출.
 *
 *   1단계: sa_family(2 bytes) 만 먼저 읽어 AF_INET / AF_INET6 판별.
 *   2단계: 확인된 family 에 맞는 크기의 구조체를 한 번에 읽음.
 *
 *   bpf_probe_read_user():
 *     첫 번째 인자: 목적지 (BPF 스택 또는 맵 슬롯)
 *     세 번째 인자: 유저 VA 포인터
 *     SMAP(Supervisor Mode Access Prevention) 우회를 BPF 런타임이 처리.
 */
static __always_inline int parse_and_submit(__u32 type,
                                             const void *uaddr)
{
    __u16 family;

    /* Step 1: family 필드만 먼저 읽기 (2 bytes) */
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return 0;

    if (family != AF_INET && family != AF_INET6)
        return 0; /* AF_UNIX, AF_NETLINK 등 비IP 소켓 제외 */

    struct net_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type   = type;
    e->pid    = (__u32)(pid_tgid >> 32);
    e->uid    = (__u32)bpf_get_current_uid_gid();
    e->family = family;
    e->ts_ns  = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Step 2: family 별로 전체 sockaddr 읽기 */
    if (family == AF_INET) {
        struct edr_sockaddr_in sa4;
        if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->dport = sa4.port;                     /* 이미 big-endian */
        __builtin_memcpy(e->daddr, sa4.addr, 4);
        __builtin_memset(e->daddr + 4, 0, 12);  /* 나머지 12바이트 0으로 */
    } else {
        struct edr_sockaddr_in6 sa6;
        if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->dport = sa6.port;
        __builtin_memcpy(e->daddr, sa6.addr, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── [1] connect(): 아웃바운드 연결 시도 ────────────────────────────────────
 *
 * sys_enter_connect 인자:
 *   args[0] = sockfd    : 소켓 파일 디스크립터
 *   args[1] = uservaddr : struct sockaddr __user * (유저스페이스 포인터)
 *   args[2] = addrlen   : sizeof(sockaddr_in) 또는 sizeof(sockaddr_in6)
 *
 * 주의: 이 훅은 연결 "시도" 시점에 발화한다.
 *   - ECONNREFUSED: 상대방 포트 닫힘
 *   - ETIMEDOUT: 방화벽 드롭 등
 *   → 실패 케이스도 포착되므로 EDR 에서는 오히려 더 가치 있다.
 *
 * TCP connect는 tcp_v4_connect()에서 SYN을 보내고 블록하지만,
 * 논블로킹(O_NONBLOCK) 소켓은 EINPROGRESS를 즉시 반환한다.
 * 두 경우 모두 sys_enter_connect 는 한 번 발화한다.
 */
SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    return parse_and_submit(EVENT_NET_CONNECT, (const void *)ctx->args[1]);
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
