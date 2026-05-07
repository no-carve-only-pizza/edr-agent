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
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <getopt.h>

#include <bpf/libbpf.h>

#include "process_monitor.skel.h"
#include "file_monitor.skel.h"
#include "network_monitor.skel.h"
#include "common.h"
#include "rules/rule_engine.h"
#include "output/json_fmt.h"
#include "output/http_reporter.h"
#include "proc_tree.h"

/* ── 전역 상태 ─────────────────────────────────────────────────────────── */

static volatile bool g_running = true;
static FILE         *g_logfile  = nullptr;
static HttpReporter *g_reporter = nullptr;
static ProcTree      g_proc_tree;

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

static uint64_t g_n_proc = 0, g_n_file = 0, g_n_net = 0;
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

#define RESET  "\033[0m"
#define BOLD   "\033[1m"

/* alert 배열을 터미널에 출력 */
static void print_alerts(const std::vector<RuleMatch> &hits)
{
    for (const auto &h : hits) {
        printf("  %s%s[ALERT] %s | %s%s\n",
               BOLD, severity_color(h.severity),
               h.id, h.name, RESET);
    }
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

    char ip[INET6_ADDRSTRLEN] = {};
    inet_ntop((e.family == 10) ? AF_INET6 : AF_INET, e.daddr, ip, sizeof(ip));
    uint16_t port = ntohs(e.dport);

    if (e.type == EVENT_NET_CONNECT)
        printf("[CONN ] %9.3fs  PID=%-6u %-12s  %-16s  → %s:%u\n",
               ts, e.pid, uid_name(e.uid), e.comm, ip, port);
    else
        printf("[BIND ] %9.3fs  PID=%-6u %-12s  %-16s  *:%u\n",
               ts, e.pid, uid_name(e.uid), e.comm, port);

    print_alerts(hits);
    emit(to_json(e, hits), alert);
    return 0;
}

static int handle_exit_event(void *, void *data, size_t sz)
{
    if (sz < sizeof(exit_event)) return 0;
    const auto &e = *static_cast<const exit_event *>(data);
    g_proc_tree.remove(e.pid);
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
        "  --alerts-only      HTTP 전송: alert 있는 이벤트만 전송\n"
        "  --help             이 도움말\n", prog);
}

int main(int argc, char **argv)
{
    /* ── 인자 파싱 ────────────────────────────────────────────────────── */
    std::string endpoint, token, logpath;
    bool alerts_only = false;

    static const option longopts[] = {
        {"endpoint",    required_argument, nullptr, 'e'},
        {"token",       required_argument, nullptr, 't'},
        {"log",         required_argument, nullptr, 'l'},
        {"alerts-only", no_argument,       nullptr, 'a'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "e:t:l:ah", longopts, nullptr)) != -1) {
        switch (opt) {
        case 'e': endpoint    = optarg; break;
        case 't': token       = optarg; break;
        case 'l': logpath     = optarg; break;
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

    /* ── 시그널 & libbpf ──────────────────────────────────────────────── */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(libbpf_print_cb);

    /* ── BPF 스켈레톤 로드 ────────────────────────────────────────────── */
    process_monitor_bpf *proc_skel = nullptr;
    file_monitor_bpf    *file_skel = nullptr;
    network_monitor_bpf *net_skel  = nullptr;
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

    /* ── 통합 링버퍼 폴러 ─────────────────────────────────────────────── */
    rb = ring_buffer__new(bpf_map__fd(proc_skel->maps.rb),
                          handle_proc_event, nullptr, nullptr);
    if (!rb) { err = -1; goto cleanup; }

    if ((err = ring_buffer__add(rb, bpf_map__fd(file_skel->maps.rb),
                                handle_file_event,  nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(net_skel->maps.rb),
                                handle_net_event,   nullptr)) < 0) goto cleanup;
    if ((err = ring_buffer__add(rb, bpf_map__fd(proc_skel->maps.rb_exit),
                                handle_exit_event,  nullptr)) < 0) goto cleanup;

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
    while (g_running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0)       { fprintf(stderr, "[!] poll 에러: %d\n", err); break; }
    }

    printf("\n[*] 종료 중...\n");
    ring_buffer__consume(rb);  /* 폴 루프 종료 후 남은 이벤트 드레인 */
    if (g_reporter) g_reporter->flush();

    /* ── 세션 통계 출력 ────────────────────────────────────────────────── */
    uint64_t total = g_n_proc + g_n_file + g_n_net;
    printf("\n" BOLD "=== 세션 통계 ===\n" RESET);
    printf("총 이벤트: %" PRIu64 "  (EXEC=%" PRIu64 "  FILE=%" PRIu64 "  NET=%" PRIu64 ")\n",
           total, g_n_proc, g_n_file, g_n_net);

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
    ring_buffer__free(rb);
    network_monitor_bpf__destroy(net_skel);
    file_monitor_bpf__destroy(file_skel);
    process_monitor_bpf__destroy(proc_skel);
    if (g_logfile) fclose(g_logfile);
    return (err < 0) ? 1 : 0;
}
