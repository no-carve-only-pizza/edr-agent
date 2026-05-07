/*
 * main.cpp - EDR Agent 오케스트레이터 (마일스톤 4+5 통합)
 *
 * ┌─ 전체 파이프라인 ───────────────────────────────────────────────────────┐
 * │                                                                          │
 * │  ┌──────────┐ ┌──────────┐ ┌─────────────┐                            │
 * │  │ proc BPF │ │ file BPF │ │ network BPF │  ← 3개 BPF 프로그램        │
 * │  └─────┬────┘ └─────┬────┘ └──────┬──────┘                            │
 * │        └────────────┼─────────────┘                                    │
 * │                     │ ring_buffer__poll() (epoll 통합)                  │
 * │                     ▼                                                   │
 * │             handle_*_event()                                            │
 * │                     │                                                   │
 * │          ┌──────────┼──────────┐                                       │
 * │          ▼          ▼          ▼                                        │
 * │      match_rules()  to_json()  print_event()                           │
 * │          │          │                                                   │
 * │          └──────────┘                                                   │
 * │                     │                                                   │
 * │          ┌──────────┼──────────┐                                       │
 * │          ▼          ▼          ▼                                        │
 * │        stdout    logfile    HttpReporter                                │
 * │       (table)   (NDJSON)  (HTTP POST)                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * 실행 옵션:
 *   sudo ./edr-agent [--endpoint URL] [--token TOKEN]
 *                    [--log FILE] [--alerts-only]
 */

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <pwd.h>
#include <sched.h>     /* CLONE_NEW* 상수 */
#include <string>
#include <sys/stat.h>  /* stat(): /proc/1/ns/pid inode 읽기 */
#include <unordered_map>
#include <utility>
#include <vector>
#include <getopt.h>

#include <bpf/libbpf.h>

#include "process_monitor.skel.h"
#include "file_monitor.skel.h"
#include "network_monitor.skel.h"
#include "memory_monitor.skel.h"
#include "dns_monitor.skel.h"
#include "ns_monitor.skel.h"
#include "common.h"
#include "rules/rule_engine.h"
#include "rules/rule_config.h"
#include "output/json_fmt.h"
#include "output/http_reporter.h"
#include "proc_tree.h"
#include "correlation/correlator.h"
#include "threat_intel/feed_manager.h"
#include "threat_intel/hash_checker.h"
#include "anomaly/behavior_profiler.h"
#include "action/action_server.h"
#include <ctime>
#include <sys/prctl.h>

/* ── 전역 상태 ─────────────────────────────────────────────────────────── */

static volatile bool      g_running    = true;
static FILE              *g_logfile    = nullptr;
static HttpReporter      *g_reporter   = nullptr;
static ProcTree           g_proc_tree;
static CorrelationEngine  g_correlator;
static FeedManager       *g_feeds      = nullptr;
static HashChecker       *g_hash       = nullptr;
static BehaviorProfiler   g_profiler;
static pid_t              g_agent_pid  = 0; /* self-defense: 자신의 PID */

/*
 * 알림 중복 억제 (dedup):
 *
 * 동일 룰이 단시간에 대량 발화하는 패턴(R-007 서버 바인드 연속, pip install 중
 * R-005 반복 등)을 억제하기 위해 (rule_id, comm) 쌍을 키로 마지막 발화
 * 타임스탬프를 기록한다. DEDUP_NS 이내에 같은 키가 재발화하면 출력을 건너뛴다.
 *
 * PID가 아닌 comm 으로 키잉하는 이유:
 *   PID 는 재사용될 수 있고, 같은 종류의 프로세스 인스턴스 N개가 동시에
 *   같은 룰을 트리거할 때 전부 억제하는 것이 의도된 동작이다.
 */
static std::unordered_map<std::string, uint64_t> g_dedup; /* key → last ts_ns */
static constexpr uint64_t DEDUP_NS = 3ULL * 1'000'000'000ULL; /* 3초 */

/* 이상 탐지 알림 중복 억제: 같은 (comm, metric) 은 5분 이내 재발화 억제 */
static std::unordered_map<std::string, uint64_t> g_anomaly_dedup;
static constexpr uint64_t ANOMALY_DEDUP_NS = 300ULL * 1'000'000'000ULL; /* 5분 */

/* ── UID → 사용자 이름 캐시 ─────────────────────────────────────────────── */

/*
 * uid_name(): UID를 사용자 이름으로 변환. 결과를 정적 캐시에 보관.
 *
 * getpwuid_r(): thread-safe 버전. 내부 정적 버퍼를 쓰지 않는다.
 * 반환된 포인터는 캐시 내 string 의 c_str() 이므로 다음 호출 전까지 유효.
 */
static const char *uid_name(uint32_t uid)
{
    static std::unordered_map<uint32_t, std::string> cache;
    auto it = cache.find(uid);
    if (it != cache.end()) return it->second.c_str();

    char buf[256];
    struct passwd pw, *result = nullptr;
    if (getpwuid_r(uid, &pw, buf, sizeof(buf), &result) == 0 && result)
        cache[uid] = result->pw_name;
    else
        cache[uid] = std::to_string(uid); /* 매핑 없으면 숫자 그대로 */
    return cache[uid].c_str();
}

/* ── 세션 통계 ──────────────────────────────────────────────────────────── */

static uint64_t g_n_proc = 0, g_n_file = 0, g_n_net = 0, g_n_mem = 0, g_n_dns = 0, g_n_ns = 0;
static std::unordered_map<std::string, uint32_t> g_rule_counts;

static std::vector<RuleMatch> dedup_alerts(std::vector<RuleMatch> hits,
                                            const char *comm, uint64_t ts_ns)
{
    auto end = std::remove_if(hits.begin(), hits.end(),
        [&](const RuleMatch &h) {
            std::string key = std::string(h.id) + ":" + comm;
            auto it = g_dedup.find(key);
            if (it != g_dedup.end() && ts_ns - it->second < DEDUP_NS)
                return true;
            g_dedup[key] = ts_ns;
            return false;
        });
    hits.erase(end, hits.end());
    return hits;
}

static void sig_handler(int) { g_running = false; }

static int libbpf_print_cb(enum libbpf_print_level level,
                            const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, args);
}

/* ── 출력 헬퍼 ─────────────────────────────────────────────────────────── */

#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define MAGENTA "\033[1;35m"
#define CYAN    "\033[1;36m"

/* alert 배열을 터미널에 출력 */
static void print_alerts(const std::vector<RuleMatch> &hits)
{
    for (const auto &h : hits) {
        printf("  %s%s[ALERT] %s | %s%s\n",
               BOLD, severity_color(h.severity),
               h.id, h.name, RESET);
    }
}

/*
 * is_tmp_path(): 임시 디렉터리 경로 판별.
 * 드로퍼 패턴(R-020/R-021) 탐지용으로 상관 분석기에 이벤트를 공급할 때 사용.
 */
static bool is_tmp_path(const char *path)
{
    return strncmp(path, "/tmp/",     5) == 0 ||
           strncmp(path, "/dev/shm/", 9) == 0 ||
           strncmp(path, "/var/tmp/", 9) == 0 ||
           strncmp(path, "/run/shm/", 9) == 0;
}

/* 공통 후처리: JSON 직렬화 → 로그 파일 → HTTP 리포터 */
static void emit(const std::string &json, bool has_alert)
{
    if (g_logfile) {
        fprintf(g_logfile, "%s\n", json.c_str());
        fflush(g_logfile);
    }
    if (g_reporter)
        g_reporter->submit(json, has_alert);
}

/*
 * emit_correlation(): 상관 분석 알림 출력 + JSON 전송.
 *
 * 일반 이벤트와 달리 두 이벤트의 조합으로 생성되므로 type="correlation" 으로 직렬화.
 * 출력 색상: 자홍(magenta) — 단일 이벤트 알림보다 더 눈에 띄도록.
 */
static void emit_correlation(uint32_t pid, const char *comm, uint64_t ts_ns,
                              const std::vector<RuleMatch> &hits)
{
    if (hits.empty()) return;

    printf("%s[CORRL]%s %9.3fs  PID=%-6u %-16s  ▶ 상관 패턴 탐지\n",
           MAGENTA, RESET, (double)ts_ns / 1e9, pid, comm);
    print_alerts(hits);

    char buf[64];
    std::string j = "{\"type\":\"correlation\"";
    snprintf(buf, sizeof(buf), "%.3f", (double)ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;
    snprintf(buf, sizeof(buf), "%u", pid);
    j += ",\"pid\":"; j += buf;
    j += ",\"comm\":"; j += json_esc(comm);
    j += ",\"alerts\":[";
    for (size_t i = 0; i < hits.size(); ++i) {
        if (i) j += ",";
        j += "{\"id\":";   j += json_esc(hits[i].id);
        j += ",\"name\":"; j += json_esc(hits[i].name);
        j += ",\"sev\":";  j += json_esc(hits[i].severity);
        j += "}";
    }
    j += "]}";
    emit(j, true);
}

/* R-025/R-026: 위협 인텔 룰 매치를 hits 에 추가 (dedup 포함) */
static void maybe_add_ti_alert(std::vector<RuleMatch> &hits,
                                const char *id, const char *name, const char *sev,
                                const char *comm, uint64_t ts_ns)
{
    std::string key = std::string(id) + ":" + comm;
    auto it = g_dedup.find(key);
    if (it != g_dedup.end() && ts_ns - it->second < DEDUP_NS) return;
    g_dedup[key] = ts_ns;
    hits.push_back({id, name, sev});
    g_rule_counts[id]++;
}

/* R-028: 이상 탐지 알림 출력 + JSON 전송 */
static void emit_anomaly(const AnomalyHit &h, uint64_t ts_ns)
{
    std::string key = h.comm + ":" + h.metric;
    auto it = g_anomaly_dedup.find(key);
    if (it != g_anomaly_dedup.end() && ts_ns - it->second < ANOMALY_DEDUP_NS) return;
    g_anomaly_dedup[key] = ts_ns;
    g_rule_counts["R-028"]++;

    printf("%s[ANOML]%s %9.3fs  comm=%-16s  metric=%-12s  obs=%.0f  mean=%.1f  z=%.1f\n",
           CYAN, RESET, (double)ts_ns / 1e9,
           h.comm.c_str(), h.metric.c_str(), h.observed, h.mean, h.zscore);
    printf("  %s%s[ALERT] R-028 | 행동 이상 탐지 (EWMA Z=%.1f, 임계값=%.1f)%s\n",
           BOLD, CYAN, h.zscore, BehaviorProfiler::Z_THRESHOLD, RESET);

    char buf[64];
    std::string j = "{\"type\":\"anomaly\"";
    snprintf(buf, sizeof(buf), "%.3f", (double)ts_ns / 1e9);
    j += ",\"ts\":"; j += buf;
    j += ",\"comm\":"; j += json_esc(h.comm.c_str());
    j += ",\"metric\":"; j += json_esc(h.metric.c_str());
    snprintf(buf, sizeof(buf), "%.2f", h.observed);
    j += ",\"observed\":"; j += buf;
    snprintf(buf, sizeof(buf), "%.2f", h.mean);
    j += ",\"mean\":"; j += buf;
    snprintf(buf, sizeof(buf), "%.2f", h.stddev);
    j += ",\"stddev\":"; j += buf;
    snprintf(buf, sizeof(buf), "%.2f", h.zscore);
    j += ",\"zscore\":"; j += buf;
    j += ",\"alerts\":[{\"id\":\"R-028\""
         ",\"name\":\"행동 이상 탐지 (EWMA 기반)\""
         ",\"sev\":\"high\"}]}";
    emit(j, true);
}

/* ── 이벤트 핸들러 ─────────────────────────────────────────────────────── */

static int handle_proc_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(process_event)) return 0;
    const auto &e = *static_cast<const process_event *>(data);

    /*
     * 부모 comm 조회 → 트리 업데이트 순서가 중요하다.
     * 조회를 먼저 해야 e.ppid 로 부모 항목을 찾을 수 있다.
     * update() 이후에는 e.pid 가 덮여쓰일 수 있다 (PID 재사용).
     */
    const char *par = g_proc_tree.comm_of(e.ppid);
    auto hits = dedup_alerts(match_rules(e, par), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    g_proc_tree.update(e.pid, e.ppid, e.comm);
    g_n_proc++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    /* R-027: 실행 파일 SHA-256 해시 → 알려진 악성 해시 DB 조회 */
    if (g_hash && g_hash->check_file(e.filename)) {
        maybe_add_ti_alert(hits, "R-027",
            "알려진 악성 파일 해시 탐지 (MalwareBazaar)", "critical",
            e.comm, e.ts_ns);
        alert = true;
    }

    g_profiler.inc_exec(e.comm);

    printf("[EXEC ] %9.3fs  PID=%-6u PPID=%-6u %-12s  %-16s  %s\n",
           (double)e.ts_ns / 1e9, e.pid, e.ppid, uid_name(e.uid), e.comm, e.filename);

    /* 부모 comm 이 알려진 경우 표시 */
    if (par)
        printf("        parent: %s\n", par);

    /* argv 출력: argc > 0 이면 캡처된 인자가 있음 */
    if (e.argc > 0) {
        printf("        argv:");
        size_t off = 0;
        for (__u32 i = 0; i < e.argc && off < MAX_ARGV_LEN; i++) {
            printf(" %s", e.argv + off);
            while (off < MAX_ARGV_LEN && e.argv[off] != '\0') off++;
            off++;
        }
        printf("\n");
    }

    print_alerts(hits);
    emit(to_json(e, hits), alert);

    /* 상관 분석: /tmp 경로 실행은 드로퍼 패턴의 핵심 지표 */
    if (is_tmp_path(e.filename)) {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::EXEC_TMP, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
    }
    return 0;
}

static std::string decode_flags(__u32 f)
{
    std::string s;
    auto a = [&](const char *n){ if (!s.empty()) s += '|'; s += n; };
    if (f & 0x001) a("WRITE");
    if (f & 0x002) a("RDWR");
    if (f & 0x040) a("CREAT");
    if (f & 0x200) a("TRUNC");
    if (f & 0x400) a("APPEND");
    return s.empty() ? "0" : s;
}

static int handle_file_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(file_event)) return 0;
    const auto &e = *static_cast<const file_event *>(data);

    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    double ts = (double)e.ts_ns / 1e9;
    g_n_file++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    switch (e.type) {
    case EVENT_FILE_WRITE:
        printf("[WRITE] %9.3fs  PID=%-6u %-12s  %-16s  [%s] %s\n",
               ts, e.pid, uid_name(e.uid), e.comm, decode_flags(e.flags).c_str(), e.path);
        break;
    case EVENT_FILE_DELETE:
        printf("[DELET] %9.3fs  PID=%-6u %-12s  %-16s  %s\n",
               ts, e.pid, uid_name(e.uid), e.comm, e.path);
        break;
    case EVENT_FILE_RENAME:
        printf("[RENAM] %9.3fs  PID=%-6u %-12s  %-16s  %s  →  %s\n",
               ts, e.pid, uid_name(e.uid), e.comm, e.path, e.path2);
        break;
    }

    print_alerts(hits);
    emit(to_json(e, hits), alert);

    /* 상관 분석: /tmp 쓰기는 다운로드+실행 패턴의 첫 단계 */
    if (e.type == EVENT_FILE_WRITE && is_tmp_path(e.path)) {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::WRITE_TMP, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
    }

    if (e.type == EVENT_FILE_WRITE)
        g_profiler.inc_file_write(e.comm);

    return 0;
}

static int handle_net_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(net_event)) return 0;
    const auto &e = *static_cast<const net_event *>(data);

    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    double ts  = (double)e.ts_ns / 1e9;
    g_n_net++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    /* R-025: Feodo Tracker C2 IP 연결 탐지 (IPv4 only) */
    if (g_feeds && e.type == EVENT_NET_CONNECT && e.family == 2 /* AF_INET */) {
        uint32_t ip4;
        memcpy(&ip4, e.daddr, 4); /* network byte order */
        if (g_feeds->is_c2_ip4(ip4))
            maybe_add_ti_alert(hits, "R-025",
                "알려진 C2 서버 IP 연결 탐지 (Feodo Tracker)", "critical",
                e.comm, e.ts_ns);
        alert = !hits.empty();
    }

    char ip[INET6_ADDRSTRLEN] = {};
    inet_ntop((e.family == 10) ? AF_INET6 : AF_INET, e.daddr, ip, sizeof(ip));
    uint16_t port = ntohs(e.dport);

    /*
     * IPv4-mapped IPv6 주소 정규화: "::ffff:1.2.3.4" → "1.2.3.4"
     * connect(AF_INET6) 소켓이 IPv4 주소에 연결할 때 커널이 자동 변환한다.
     * 접두사를 제거하면 규칙 매칭과 출력이 IPv4와 일관된다.
     */
    const char *ip_display = ip;
    if (strncmp(ip, "::ffff:", 7) == 0)
        ip_display = ip + 7;

    if (e.type == EVENT_NET_CONNECT)
        printf("[CONN ] %9.3fs  PID=%-6u %-12s  %-16s  → %s:%u\n",
               ts, e.pid, uid_name(e.uid), e.comm, ip_display, port);
    else
        printf("[BIND ] %9.3fs  PID=%-6u %-12s  %-16s  *:%u\n",
               ts, e.pid, uid_name(e.uid), e.comm, port);

    print_alerts(hits);
    emit(to_json(e, hits), alert);

    /* 상관 분석: 아웃바운드 연결은 C2 체크인의 공통 지표 */
    if (e.type == EVENT_NET_CONNECT) {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::NET_CONN, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
        g_profiler.inc_net_connect(e.comm);
    }
    return 0;
}

static int handle_exit_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(exit_event)) return 0;
    const auto &e = *static_cast<const exit_event *>(data);
    g_proc_tree.remove(e.pid);
    g_correlator.remove(e.pid);  /* 종료된 PID 히스토리 정리 */
    return 0;
}

static int handle_ptrace_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(ptrace_event)) return 0;
    const auto &e = *static_cast<const ptrace_event *>(data);

    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    g_n_proc++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    /* Self-Defense: 에이전트 자신을 추적하려는 시도 */
    if (g_agent_pid && e.target_pid == (uint32_t)g_agent_pid) {
        printf("\033[1;31m[SELF-DEFENSE]\033[0m PID=%-6u %-16s가 EDR 에이전트(PID=%d)를 추적 시도!\n",
               e.pid, e.comm, g_agent_pid);
        /* 추적자를 즉시 종료 */
        kill(e.pid, SIGKILL);
        fprintf(stderr, "[*] self-defense: PID %u (%s) 종료 (SIGKILL)\n", e.pid, e.comm);
    }

    printf("[PTRAC] %9.3fs  PID=%-6u %-12s  %-16s  → target PID=%u\n",
           (double)e.ts_ns / 1e9, e.pid, uid_name(e.uid), e.comm, e.target_pid);

    print_alerts(hits);
    emit(to_json(e, hits), alert);

    /* 상관 분석: ptrace 는 인젝션 체인(R-019)의 핵심 지표 */
    {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::PTRACE, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
    }
    return 0;
}

static int handle_mem_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(memory_event)) return 0;
    const auto &e = *static_cast<const memory_event *>(data);

    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    g_n_mem++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    printf("[MEM  ] %9.3fs  PID=%-6u %-12s  %-16s  %s (prot=%u)\n",
           (double)e.ts_ns / 1e9, e.pid, uid_name(e.uid), e.comm,
           e.is_mprotect ? "mprotect" : "mmap", e.prot);

    print_alerts(hits);
    emit(to_json(e, hits), alert);

    /* 상관 분석: RWX 메모리 할당은 파일리스 C2(R-022)의 지표 */
    {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::MEM_RWX, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
    }
    return 0;
}

static int handle_dns_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(dns_event)) return 0;
    const auto &e = *static_cast<const dns_event *>(data);

    /*
     * DNS 이벤트는 빈도가 매우 높다 (브라우저 하나만 켜도 수백 건/분).
     * alert 없는 이벤트는 stdout 출력을 생략해 노이즈를 줄인다.
     */
    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    g_n_dns++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    /* R-026: URLhaus 악성 도메인 DNS 조회 탐지 */
    if (g_feeds && g_feeds->is_malicious_domain(e.name)) {
        maybe_add_ti_alert(hits, "R-026",
            "악성 도메인 DNS 조회 탐지 (URLhaus)", "critical",
            e.comm, e.ts_ns);
        alert = true;
    }

    if (alert) {
        printf("[DNS  ] %9.3fs  PID=%-6u %-12s  %-16s  %s\n",
               (double)e.ts_ns / 1e9, e.pid, uid_name(e.uid), e.comm, e.name);
        print_alerts(hits);
    }

    emit(to_json(e, hits), alert);

    /* 상관 분석: 의심 DNS 조회는 C2 비콘(R-023)의 첫 단계 */
    if (alert) {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::DNS_SUSP, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
    }
    return 0;
}

static int handle_memfd_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(memfd_event)) return 0;
    const auto &e = *static_cast<const memfd_event *>(data);

    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    g_n_mem++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    printf("[MEMFD] %9.3fs  PID=%-6u %-12s  %-16s  name=%s flags=0x%x\n",
           (double)e.ts_ns / 1e9, e.pid, uid_name(e.uid), e.comm,
           e.name[0] ? e.name : "(empty)", e.flags);

    print_alerts(hits);
    emit(to_json(e, hits), alert);

    /* 상관 분석: memfd 는 인젝션 체인(R-019)의 핵심 지표 */
    {
        auto ch = g_correlator.feed(e.pid, CorrelEvt::MEMFD, e.ts_ns);
        emit_correlation(e.pid, e.comm, e.ts_ns, ch);
    }
    return 0;
}

static int handle_ns_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(ns_event)) return 0;
    const auto &e = *static_cast<const ns_event *>(data);

    auto hits = dedup_alerts(match_rules(e), e.comm, e.ts_ns);
    bool alert = !hits.empty();
    g_n_ns++;
    for (const auto &h : hits) g_rule_counts[h.id]++;

    /* unshare() 에 설정된 네임스페이스 플래그 이름 조합 */
    std::string ns_names;
    if (e.flags & CLONE_NEWUSER)   ns_names += "user ";
    if (e.flags & CLONE_NEWPID)    ns_names += "pid ";
    if (e.flags & CLONE_NEWNS)     ns_names += "mnt ";
    if (e.flags & CLONE_NEWNET)    ns_names += "net ";
    if (e.flags & CLONE_NEWIPC)    ns_names += "ipc ";
    if (e.flags & CLONE_NEWUTS)    ns_names += "uts ";
    if (e.flags & CLONE_NEWCGROUP) ns_names += "cgroup ";
    if (!ns_names.empty() && ns_names.back() == ' ')
        ns_names.pop_back();

    printf("[UNSHR] %9.3fs  PID=%-6u %-12s  %-16s  ns=[%s]%s\n",
           (double)e.ts_ns / 1e9, e.pid, uid_name(e.uid), e.comm,
           ns_names.c_str(),
           e.in_container ? "  \033[1;31m[IN CONTAINER]\033[0m" : "");

    print_alerts(hits);
    emit(to_json(e, hits), alert);
    return 0;
}

/* ── BPF 로드 헬퍼 (중복 제거) ─────────────────────────────────────────── */

template<typename Skel>
static int load_and_attach(Skel **out, const char *name,
                            Skel *(*open_fn)(),
                            int   (*load_fn)(Skel *),
                            int   (*attach_fn)(Skel *))
{
    *out = open_fn();
    if (!*out) { fprintf(stderr, "[!] %s open 실패\n", name); return -1; }

    int err = load_fn(*out);
    if (err) { fprintf(stderr, "[!] %s load 실패: %s\n", name, strerror(-err)); return err; }

    err = attach_fn(*out);
    if (err) { fprintf(stderr, "[!] %s attach 실패: %s\n", name, strerror(-err)); return err; }

    return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "사용법: sudo %s [옵션]\n"
        "  --endpoint URL     HTTP 전송 엔드포인트  (예: http://localhost:8888)\n"
        "  --token    TOKEN   Bearer 인증 토큰\n"
        "  --log      FILE    NDJSON 이벤트 로그 파일 경로\n"
        "  --rules    FILE    YAML 룰 설정 파일 (기본값: 내장 기본값 사용)\n"
        "  --socket   PATH    명령 수신 소켓 경로 (기본값: /run/edr-agent.sock)\n"
        "  --alerts-only      HTTP 전송: alert 있는 이벤트만 전송\n"
        "  --help             이 도움말\n", prog);
}

int main(int argc, char **argv)
{
    /* ── 인자 파싱 ────────────────────────────────────────────────────── */
    std::string endpoint, token, logpath, rulespath;
    std::string sockpath = ActionServer::DEFAULT_SOCK;
    bool alerts_only = false;

    static const option longopts[] = {
        {"endpoint",    required_argument, nullptr, 'e'},
        {"token",       required_argument, nullptr, 't'},
        {"log",         required_argument, nullptr, 'l'},
        {"rules",       required_argument, nullptr, 'r'},
        {"socket",      required_argument, nullptr, 's'},
        {"alerts-only", no_argument,       nullptr, 'a'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "e:t:l:r:s:ah", longopts, nullptr)) != -1) {
        switch (opt) {
        case 'e': endpoint    = optarg; break;
        case 't': token       = optarg; break;
        case 'l': logpath     = optarg; break;
        case 'r': rulespath   = optarg; break;
        case 's': sockpath    = optarg; break;
        case 'a': alerts_only = true;   break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    /* ── 출력 대상 초기화 ─────────────────────────────────────────────── */
    if (!logpath.empty()) {
        g_logfile = fopen(logpath.c_str(), "a");
        if (!g_logfile)
            fprintf(stderr, "[!] 로그 파일 열기 실패: %s\n", strerror(errno));
        else
            fprintf(stderr, "[*] 이벤트 로그: %s\n", logpath.c_str());
    }

    HttpReporter reporter(endpoint, token, alerts_only);
    if (reporter.active()) g_reporter = &reporter;

    /* ── 룰 초기화 ──────────────────────────────────────────────────────
     *
     * 1. 내장 기본값으로 초기화 (항상 수행)
     * 2. --rules FILE 이 지정된 경우 YAML 파일로 덮어씀
     *
     * load() 가 false 를 반환(파일 없음)해도 기본값이 이미 로드되어 있으므로
     * 계속 실행할 수 있다.
     */
    RuleConfig g_rules;
    if (!rulespath.empty()) {
        /*
         * --rules 지정 시: YAML 파일로 완전 교체.
         * 파일 열기 실패 시에만 기본값으로 폴백.
         */
        if (g_rules.load(rulespath))
            fprintf(stderr, "[*] 룰 설정 로드: %s\n", rulespath.c_str());
        else {
            fprintf(stderr, "[!] 룰 파일 열기 실패: %s — 내장 기본값 사용\n",
                    rulespath.c_str());
            g_rules.load_defaults();
        }
    } else {
        g_rules.load_defaults();
    }
    init_rules(g_rules);

    /* ── 위협 인텔리전스 초기화 ─────────────────────────────────────────
     *
     * FeedManager: 백그라운드 스레드로 Feodo Tracker IP 피드와 URLhaus 도메인
     * 피드를 주기적으로 갱신한다. start() 는 즉시 반환하고 첫 페치는 백그라운드에서
     * 실행되므로 에이전트 시작 지연 없음.
     *
     * HashChecker: known_hashes.txt 를 메모리에 로드한다.
     * 해시 DB 경로가 없으면 R-027 비활성화.
     */
    FeedManager feed_mgr(g_rules.ip_feed_url,
                         g_rules.domain_feed_url,
                         g_rules.feed_update_hours);
    feed_mgr.start();
    g_feeds = &feed_mgr;
    fprintf(stderr, "[*] 위협 인텔 피드 시작 (갱신 주기: %dh)\n",
            g_rules.feed_update_hours);
    fprintf(stderr, "    IP 피드: %s\n",    g_rules.ip_feed_url.c_str());
    fprintf(stderr, "    도메인 피드: %s\n", g_rules.domain_feed_url.c_str());

    HashChecker hash_chk;
    if (!g_rules.hash_db_path.empty()) {
        if (hash_chk.load(g_rules.hash_db_path))
            fprintf(stderr, "[*] 해시 DB 로드: %s (%zu 개)\n",
                    g_rules.hash_db_path.c_str(), hash_chk.count());
        else
            fprintf(stderr, "[!] 해시 DB 열기 실패: %s\n",
                    g_rules.hash_db_path.c_str());
        g_hash = &hash_chk;
    }

    /* ── Self-Defense 초기화 ────────────────────────────────────────────
     *
     * 1. PR_SET_DUMPABLE=0: /proc/<pid>/mem 접근 차단.
     *    비루트 프로세스가 ptrace(ATTACH)를 시도하면 EPERM 으로 차단된다.
     *    (루트 프로세스는 여전히 추적 가능 — BPF 훅으로 감지 후 즉시 종료)
     *
     * 2. g_agent_pid 저장: ptrace 이벤트 핸들러에서 자신을 추적하는
     *    시도를 감지하면 추적자를 SIGKILL로 즉시 종료한다.
     */
    g_agent_pid = getpid();
    if (prctl(PR_SET_DUMPABLE, 0) == 0)
        fprintf(stderr, "[*] self-defense: PR_SET_DUMPABLE=0 (ptrace 방어 활성화)\n");
    else
        fprintf(stderr, "[!] self-defense: prctl 실패: %s\n", strerror(errno));

    /* ── ActionServer 초기화 ─────────────────────────────────────────── */
    ActionServer action_server(sockpath);
    action_server.set_stats_fn([&]() -> AgentStats {
        return {g_n_proc, g_n_file, g_n_net, g_n_mem, g_n_dns, g_n_ns};
    });
    action_server.start();

    /* ── 시그널 & libbpf ──────────────────────────────────────────────── */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(libbpf_print_cb);

    /* ── BPF 스켈레톤 로드 ────────────────────────────────────────────── */
    process_monitor_bpf *proc_skel = nullptr;
    file_monitor_bpf    *file_skel = nullptr;
    network_monitor_bpf *net_skel  = nullptr;
    memory_monitor_bpf  *mem_skel  = nullptr;
    dns_monitor_bpf     *dns_skel  = nullptr;
    ns_monitor_bpf      *ns_skel   = nullptr;
    ring_buffer         *rb        = nullptr;
    int err = 0;

    if ((err = load_and_attach(&proc_skel, "process_monitor",
            process_monitor_bpf__open,
            process_monitor_bpf__load,
            process_monitor_bpf__attach)) < 0) goto cleanup;

    if ((err = load_and_attach(&file_skel, "file_monitor",
            file_monitor_bpf__open,
            file_monitor_bpf__load,
            file_monitor_bpf__attach)) < 0) goto cleanup;

    if ((err = load_and_attach(&net_skel, "network_monitor",
            network_monitor_bpf__open,
            network_monitor_bpf__load,
            network_monitor_bpf__attach)) < 0) goto cleanup;

    if ((err = load_and_attach(&mem_skel, "memory_monitor",
            memory_monitor_bpf__open,
            memory_monitor_bpf__load,
            memory_monitor_bpf__attach)) < 0) goto cleanup;

    if ((err = load_and_attach(&dns_skel, "dns_monitor",
            dns_monitor_bpf__open,
            dns_monitor_bpf__load,
            dns_monitor_bpf__attach)) < 0) goto cleanup;

    if ((err = load_and_attach(&ns_skel, "ns_monitor",
            ns_monitor_bpf__open,
            ns_monitor_bpf__load,
            ns_monitor_bpf__attach)) < 0) goto cleanup;

    /*
     * init PID 네임스페이스 inum 을 BPF 맵에 기록.
     *
     * /proc/1/ns/pid 는 init 프로세스의 PID 네임스페이스를 가리키는 심볼릭 링크다.
     * stat() 로 inode 번호를 읽어 BPF 맵(init_pid_ns_inum)에 저장하면,
     * BPF 훅이 현재 프로세스의 PID ns inode 와 비교해 컨테이너 여부를 판단한다.
     */
    {
        struct stat ns_st;
        if (stat("/proc/1/ns/pid", &ns_st) == 0) {
            uint64_t inum = (uint64_t)ns_st.st_ino;
            uint32_t key  = 0;
            bpf_map__update_elem(ns_skel->maps.init_pid_ns_inum,
                                 &key, sizeof(key),
                                 &inum, sizeof(inum), BPF_ANY);
            fprintf(stderr, "[*] init PID ns inum: %" PRIu64 "\n", inum);
        } else {
            fprintf(stderr, "[!] /proc/1/ns/pid stat 실패: %s\n", strerror(errno));
        }
    }

    /* ── 통합 링버퍼 폴러 ─────────────────────────────────────────────── */
    rb = ring_buffer__new(bpf_map__fd(proc_skel->maps.rb),
                          handle_proc_event, nullptr, nullptr);
    if (!rb) { err = -1; goto cleanup; }

    if ((err = ring_buffer__add(rb, bpf_map__fd(file_skel->maps.rb),
                                handle_file_event,  nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(net_skel->maps.rb),
                                handle_net_event,   nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(proc_skel->maps.rb_exit),
                                handle_exit_event,   nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(proc_skel->maps.rb_ptrace),
                                handle_ptrace_event, nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(mem_skel->maps.rb_mem),
                                handle_mem_event,   nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(mem_skel->maps.rb_memfd),
                                handle_memfd_event, nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(dns_skel->maps.rb_dns),
                                handle_dns_event,   nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(ns_skel->maps.rb_ns),
                                handle_ns_event,    nullptr)) < 0) goto cleanup;

    /* ── 프로세스 트리 초기화 ────────────────────────────────────────────
     *
     * BPF 훅이 attach 되기 전부터 실행 중인 프로세스(nginx, mysqld 등)는
     * exec 이벤트가 없으므로 트리에 자동 추가되지 않는다.
     * /proc 스캔으로 기존 프로세스를 미리 채워 R-011/R-012 탐지를 즉시 활성화.
     */
    g_proc_tree.init_from_proc();
    fprintf(stderr, "[*] 프로세스 트리 초기화: %zu 개 항목\n", g_proc_tree.size());

    /* ── 헤더 출력 ────────────────────────────────────────────────────── */
    printf(BOLD
        "+----------------------------------------------------------------------+\n"
        "|   EDR Agent  ·  Process + File + Network  (eBPF)                    |\n"
        "|   Ctrl+C 로 종료                                                    |\n"
        "+----------------------------------------------------------------------+\n"
        RESET);
    printf("%-8s %-10s %-8s %-12s  %-16s  %s\n",
           "TYPE", "TIME(s)", "PID", "USER", "COMM", "PATH / DEST");
    printf("%s\n", std::string(72, '-').c_str());

    /* ── 이벤트 폴 루프 ───────────────────────────────────────────────── */
    uint64_t last_anomaly_tick = (uint64_t)time(nullptr);
    while (g_running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0)       { fprintf(stderr, "[!] poll 에러: %d\n", err); break; }

        /* R-028: 60초 윈도우마다 이상 탐지 점수 계산 */
        uint64_t now_sec = (uint64_t)time(nullptr);
        if (now_sec - last_anomaly_tick >= 30) {
            last_anomaly_tick = now_sec;
            uint64_t ts_ns = (uint64_t)now_sec * 1'000'000'000ULL;
            for (const auto &h : g_profiler.tick(now_sec))
                emit_anomaly(h, ts_ns);
        }
    }

    printf("\n[*] 종료 중...\n");
    ring_buffer__consume(rb);  /* 폴 루프 종료 후 남은 이벤트 드레인 */
    if (g_reporter) g_reporter->flush();

    /* ── 세션 통계 출력 ────────────────────────────────────────────────── */
    uint64_t total = g_n_proc + g_n_file + g_n_net + g_n_mem + g_n_dns + g_n_ns;
    printf("\n" BOLD "=== 세션 통계 ===\n" RESET);
    printf("총 이벤트: %" PRIu64
           "  (EXEC=%" PRIu64 "  FILE=%" PRIu64
           "  NET=%" PRIu64 "  MEM=%" PRIu64
           "  DNS=%" PRIu64 "  NS=%" PRIu64 ")\n",
           total, g_n_proc, g_n_file, g_n_net, g_n_mem, g_n_dns, g_n_ns);

    if (!g_rule_counts.empty()) {
        printf("\n%-10s  %s\n", "룰", "발화 횟수");
        printf("%s\n", std::string(28, '-').c_str());
        std::vector<std::pair<std::string, uint32_t>> sorted(
            g_rule_counts.begin(), g_rule_counts.end());
        std::sort(sorted.begin(), sorted.end(),
            [](const auto &a, const auto &b){ return a.second > b.second; });
        for (const auto &kv : sorted)
            printf("%-10s  %u 회\n", kv.first.c_str(), kv.second);
    } else {
        printf("알림 없음\n");
    }

cleanup:
    action_server.stop();
    g_feeds = nullptr;
    feed_mgr.stop();
    g_hash  = nullptr;
    ring_buffer__free(rb);
    ns_monitor_bpf__destroy(ns_skel);
    dns_monitor_bpf__destroy(dns_skel);
    memory_monitor_bpf__destroy(mem_skel);
    network_monitor_bpf__destroy(net_skel);
    file_monitor_bpf__destroy(file_skel);
    process_monitor_bpf__destroy(proc_skel);
    if (g_logfile) fclose(g_logfile);
    return (err < 0) ? 1 : 0;
}
