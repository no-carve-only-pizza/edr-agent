// SPDX-License-Identifier: GPL-2.0
/*
 * dns_monitor.bpf.c - EDR Agent: DNS 쿼리 감시 BPF 커널 프로그램
 *
 * ┌─ 탐지 원리 ─────────────────────────────────────────────────────────────┐
 * │                                                                          │
 * │  표준 DNS 쿼리 흐름:                                                     │
 * │    유저: getaddrinfo("evil.com")                                         │
 * │      → glibc resolver → sendto(sock, dns_query, ..., &nameserver:53)   │
 * │      → sys_enter_sendto ★ BPF 훅                                        │
 * │      → 커널 UDP 스택 → 네트워크 전송                                    │
 * │                                                                          │
 * │  탐지 대상:                                                              │
 * │    - DNS 터널링: iodine, dnscat2 등이 서브도메인에 데이터를 인코딩.    │
 * │      레이블 길이 > 50자 = 데이터 페이로드 확실.                         │
 * │    - DGA (Domain Generation Algorithm): 악성코드 C2 서버를 랜덤 도메인   │
 * │      으로 동적 생성. 모음 없는 긴 서브도메인이 전형적 지표.             │
 * │    - 남용 TLD: .tk/.ml/.ga/.cf 는 무료 등록 가능해 피싱/C2 에 자주 쓰임│
 * │                                                                          │
 * │  한계:                                                                   │
 * │    - DNS over HTTPS (DoH): HTTPS 내부에 캡슐화 → 이 훅으로 감지 불가   │
 * │    - DNS over TCP (DoT): sendto 대신 send() 사용 시 dest_addr=NULL      │
 * │      → 포트 53 확인 불가로 미감지. TCP 기반 DNS 터널링 보완 필요.      │
 * │    - DNS 압축 포인터(0xC0~): QNAME 파싱에서 제외 (단순화).             │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * BPF QNAME 파싱 전략:
 *   DNS 와이어 포맷 QNAME: <len><label><len><label>...<0x00>
 *   BPF 스택에 128바이트 버퍼를 올려 UDP 페이로드를 읽은 뒤,
 *   AND 마스크(& 127)로 배열 접근 경계를 검증기에게 정적으로 증명한다.
 *   점(.) 구분 문자열로 변환하여 dns_event.name 에 저장.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>  /* bpf_htons() */
#include "common.h"

#define AF_INET  2
#define AF_INET6 10

/*
 * DNS_BUF_LEN: BPF 스택에 올릴 DNS 페이로드 버퍼 크기.
 *
 * DNS 헤더 12바이트 + QNAME 최대 116바이트 = 128바이트.
 * 2의 거듭제곱이므로 AND 마스크(& 127)로 검증기 경계 증명에 활용한다.
 * BPF 스택(512B) 여유: raw[128] + 지역변수(~32B) ≈ 160B.
 */
#define DNS_BUF_LEN 128

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB: DNS 쿼리는 빈도가 높음 */
} rb_dns SEC(".maps");

/*
 * sys_enter_sendto 인자:
 *   args[0] = sockfd
 *   args[1] = buf        (전송 데이터 버퍼, UDP 페이로드)
 *   args[2] = len        (버퍼 길이)
 *   args[3] = flags
 *   args[4] = dest_addr  (struct sockaddr __user *, NULL이면 connected socket)
 *   args[5] = addrlen
 *
 * 필터링 순서 (early return으로 오버헤드 최소화):
 *   1. dest_addr != NULL (connected socket 의 send()는 포트 확인 불가)
 *   2. family == AF_INET 또는 AF_INET6
 *   3. dest port == 53 (DNS)
 *   4. DNS 플래그 QR bit == 0 (쿼리, 응답 제외)
 *   5. QDCOUNT >= 1 (질문 섹션 존재)
 */
SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx)
{
    /* ── 1. dest_addr 존재 확인 ──────────────────────────────────────────── */
    const void *uaddr = (const void *)ctx->args[4];
    if (!uaddr) return 0;

    /* ── 2. 주소 패밀리 & 포트 확인 ──────────────────────────────────────── */
    __u16 family, dport;
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0) return 0;
    if (family != AF_INET && family != AF_INET6)                 return 0;

    /*
     * sockaddr_in / sockaddr_in6 모두 오프셋 2 에 포트가 있다.
     * (sockaddr_in: family(2) + port(2) + addr(4) + pad(8))
     * (sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4))
     */
    if (bpf_probe_read_user(&dport, sizeof(dport), uaddr + 2) < 0) return 0;
    if (dport != bpf_htons(53)) return 0;

    /* ── 3. DNS 페이로드 검증 ─────────────────────────────────────────────
     *
     * UDP 페이로드 최소 크기: 12(헤더) + 1(len) + 1(label최소) + 1(null) + 4(QTYPE+QCLASS) = 19
     * 간단히 13 이상으로 체크 (QNAME 이 \x00 한 바이트 만이어도 유효).
     */
    __u64 dnsbuf_len = (__u64)ctx->args[2];
    if (dnsbuf_len < 13) return 0;

    /*
     * DNS 헤더 + QNAME 앞부분을 BPF 스택 버퍼에 복사.
     * 페이로드가 128B 미만이어도 0 패딩이 되어 안전.
     */
    const void *ubuf = (const void *)ctx->args[1];
    __u8 raw[DNS_BUF_LEN];
    __builtin_memset(raw, 0, sizeof(raw));
    if (bpf_probe_read_user(raw, sizeof(raw), ubuf) < 0) return 0;

    /*
     * DNS 플래그(bytes 2~3):
     *   bit 15 (QR): 0=쿼리, 1=응답.
     *   응답 패킷은 무시 — 유저의 "의도된 쿼리"만 탐지 대상.
     */
    __u16 flags = ((__u16)raw[2] << 8) | raw[3];
    if (flags & 0x8000) return 0;

    /* QDCOUNT(bytes 4~5): 질문 섹션 레코드 수. 0이면 빈 쿼리 → 무시. */
    __u16 qdcount = ((__u16)raw[4] << 8) | raw[5];
    if (qdcount == 0) return 0;

    /* ── 4. 링버퍼 슬롯 예약 ─────────────────────────────────────────────── */
    struct dns_event *e = bpf_ringbuf_reserve(&rb_dns, sizeof(*e), 0);
    if (!e) return 0;

    /* ── 5. 기본 필드 채우기 ─────────────────────────────────────────────── */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid    = (__u32)(pid_tgid >> 32);
    e->uid    = (__u32)bpf_get_current_uid_gid();
    e->ts_ns  = bpf_ktime_get_ns();
    e->family = family;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* DNS 서버 IP 복사 */
    if (family == AF_INET) {
        bpf_probe_read_user(e->server, 4, uaddr + 4);
        __builtin_memset(e->server + 4, 0, 12);
    } else {
        bpf_probe_read_user(e->server, 16, uaddr + 8);
    }

    /* ── 6. QNAME 파싱: 와이어 포맷 → 점 구분 문자열 ───────────────────────
     *
     * DNS 와이어 포맷 QNAME (raw[12:] 에서 시작):
     *   [len₁][label₁][len₂][label₂]...[0x00]
     *
     * 변환 예: raw = 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
     *          →    "www.google.com"
     *
     * BPF 검증기 경계 증명:
     *   raw 배열 접근: idx & (DNS_BUF_LEN - 1) → 항상 [0, 127] 범위
     *   name 배열 접근: out & (DNS_NAME_MAX - 1) → 항상 [0, 127] 범위
     *   두 배열 모두 128바이트(2의 거듭제곱)이므로 AND 마스크가 상한 증명.
     *
     * DNS 압축 포인터(len >= 0xC0): 단순화를 위해 파싱 중단.
     */
    __builtin_memset(e->name, 0, sizeof(e->name));
    __u32 out = 0;
    __u32 pos = 12; /* QNAME 시작 오프셋 */

    #pragma unroll
    for (int label = 0; label < 10; label++) {
        if (pos >= DNS_BUF_LEN) break;

        __u8 len = raw[pos & (DNS_BUF_LEN - 1)]; /* 길이 바이트 */
        if (len == 0 || len > 63) break;          /* QNAME 종료 또는 압축 포인터 */
        pos++;

        /* 레이블 사이에 점 삽입 */
        if (out > 0 && out < DNS_NAME_MAX - 1) {
            e->name[out & (DNS_NAME_MAX - 1)] = '.';
            out++;
        }

        /* 레이블 문자 복사 (최대 63자) */
        #pragma unroll
        for (int c = 0; c < 63; c++) {
            if ((__u32)c >= (__u32)len)   break;
            if (out >= DNS_NAME_MAX - 1)   break;
            __u32 src = (pos + (__u32)c) & (DNS_BUF_LEN - 1);
            e->name[out & (DNS_NAME_MAX - 1)] = (char)raw[src];
            out++;
        }
        pos += len;
    }
    /* NUL 종료: __builtin_memset 으로 이미 0 초기화됨 */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
