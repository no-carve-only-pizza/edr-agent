/*
 * json_fmt.cpp - JSON 직렬화 구현
 *
 * JSON 문자열 이스케이프 규칙 (RFC 8259 §7):
 *   \b \f \n \r \t  → 단축 이스케이프
 *   "  \            → \" \\
 *   U+0000~U+001F   → \u00XX (16진수 4자리)
 *   그 외 UTF-8 바이트 → 그대로 출력 (JSON은 UTF-8을 허용)
 */
#include "output/json_fmt.h"
#include <arpa/inet.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>

/* ── 이스케이프 헬퍼 ────────────────────────────────────────────────────── */

std::string json_esc(const char *s)
{
    std::string out;
    out.reserve(strlen(s) + 4);
    out += '"';
    for (const char *p = s; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                /* 제어문자: \u00XX */
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += (char)c;
            }
        }
    }
    out += '"';
    return out;
}

/* ── 공통 헬퍼 ──────────────────────────────────────────────────────────── */

/* alerts 배열 → JSON array 문자열. 예: [{"id":"R-001","name":"...","sev":"high"}] */
static std::string alerts_json(const std::vector<RuleMatch> &hits)
{
    std::string s = "[";
    for (size_t i = 0; i < hits.size(); ++i) {
        if (i) s += ",";
        s += "{\"id\":";   s += json_esc(hits[i].id);
        s += ",\"name\":"; s += json_esc(hits[i].name);
        s += ",\"sev\":";  s += json_esc(hits[i].severity);
        s += "}";
    }
    s += "]";
    return s;
}

/*
 * argv_json: process_event.argv (NUL 구분 버퍼) → JSON 배열 문자열.
 *
 * 입력 형식: "argv0\0argv1\0argv2\0..." (argc 개)
 * 출력 형식: ["argv0","argv1","argv2"]
 *
 * argc == 0 이면 빈 배열 "[]" 반환.
 */
static std::string argv_json(const char *buf, __u32 argc)
{
    std::string s = "[";
    size_t off = 0;
    for (__u32 i = 0; i < argc; i++) {
        if (off >= MAX_ARGV_LEN) break;
        if (i) s += ',';
        s += json_esc(buf + off);
        while (off < MAX_ARGV_LEN && buf[off] != '\0') off++;
        off++; /* NUL 건너뜀 */
    }
    return s + "]";
}

static std::string ip_str(const __u8 *addr, __u16 family)
{
    char buf[INET6_ADDRSTRLEN] = {};
    int af = (family == 10) ? AF_INET6 : AF_INET;
    inet_ntop(af, addr, buf, sizeof(buf));
    return buf;
}

/* ── 이벤트 직렬화 ──────────────────────────────────────────────────────── */

std::string to_json(const process_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    j += "\"type\":\"exec\"";

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.ppid);
    j += ",\"ppid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":";     j += json_esc(e.comm);
    j += ",\"path\":";     j += json_esc(e.filename);
    j += ",\"argv\":";     j += argv_json(e.argv, e.argc);

    snprintf(buf, sizeof(buf), "%u", e.euid);
    j += ",\"euid\":"; j += buf;

    j += ",\"ld_preload\":"; j += e.has_ld_preload ? "true" : "false";

    j += ",\"alerts\":";   j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const file_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    const char *type_str =
        (e.type == EVENT_FILE_WRITE)  ? "file_write"  :
        (e.type == EVENT_FILE_DELETE) ? "file_delete" :
        (e.type == EVENT_FILE_RENAME) ? "file_rename" : "file_unknown";

    j += "\"type\":"; j += json_esc(type_str);

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":"; j += json_esc(e.comm);
    j += ",\"path\":"; j += json_esc(e.path);

    if (e.type == EVENT_FILE_RENAME) {
        j += ",\"dst\":"; j += json_esc(e.path2);
    }

    snprintf(buf, sizeof(buf), "%u", e.flags);
    j += ",\"flags\":"; j += buf;

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const net_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    const char *type_str =
        (e.type == EVENT_NET_CONNECT) ? "net_connect" :
        (e.type == EVENT_NET_BIND)    ? "net_bind"    : "net_unknown";

    j += "\"type\":"; j += json_esc(type_str);

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":"; j += json_esc(e.comm);

    j += ",\"dst\":";  j += json_esc(ip_str(e.daddr, e.family).c_str());

    snprintf(buf, sizeof(buf), "%u", (unsigned)ntohs(e.dport));
    j += ",\"dport\":"; j += buf;

    j += ",\"family\":"; j += (e.family == 10) ? "\"ipv6\"" : "\"ipv4\"";

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const ptrace_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    j += "\"type\":\"ptrace\"";

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":"; j += json_esc(e.comm);

    snprintf(buf, sizeof(buf), "%u", e.target_pid);
    j += ",\"target_pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.request);
    j += ",\"request\":"; j += buf;

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const memfd_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    j += "\"type\":\"memfd\"";

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":"; j += json_esc(e.comm);
    j += ",\"name\":"; j += json_esc(e.name);

    snprintf(buf, sizeof(buf), "%u", e.flags);
    j += ",\"flags\":"; j += buf;

    j += ",\"sealing\":"; j += (e.flags & 0x2) ? "true" : "false";

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const dns_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    j += "\"type\":\"dns\"";

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":";   j += json_esc(e.comm);
    j += ",\"query\":";  j += json_esc(e.name);

    j += ",\"server\":"; j += json_esc(ip_str(e.server, e.family).c_str());
    j += ",\"family\":"; j += (e.family == 10) ? "\"ipv6\"" : "\"ipv4\"";

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const memory_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    j += "\"type\":\"memory\"";

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":"; j += json_esc(e.comm);

    snprintf(buf, sizeof(buf), "%u", e.prot);
    j += ",\"prot\":"; j += buf;

    j += ",\"is_mprotect\":"; j += e.is_mprotect ? "true" : "false";

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}

std::string to_json(const ns_event &e, const std::vector<RuleMatch> &hits)
{
    char buf[64];
    std::string j = "{";

    j += "\"type\":\"ns_unshare\"";

    snprintf(buf, sizeof(buf), "%.3f", (double)e.ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.pid);
    j += ",\"pid\":"; j += buf;

    snprintf(buf, sizeof(buf), "%u", e.uid);
    j += ",\"uid\":"; j += buf;

    j += ",\"comm\":"; j += json_esc(e.comm);

    snprintf(buf, sizeof(buf), "%" PRIu64, (uint64_t)e.ns_inum);
    j += ",\"ns_inum\":"; j += buf;

    snprintf(buf, sizeof(buf), "0x%x", e.flags);
    j += ",\"flags\":"; j += json_esc(buf);

    j += ",\"in_container\":"; j += e.in_container ? "true" : "false";

    j += ",\"alerts\":"; j += alerts_json(hits);
    j += "}";
    return j;
}
