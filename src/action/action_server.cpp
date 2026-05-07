#include "action/action_server.h"
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

ActionServer::ActionServer(std::string sock_path)
    : m_sock_path(std::move(sock_path)) {}

ActionServer::~ActionServer() { stop(); }

void ActionServer::start()
{
    /* Unix 도메인 소켓 생성 */
    m_srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_srv_fd < 0) {
        fprintf(stderr, "[!] action_server: socket() 실패: %s\n", strerror(errno));
        return;
    }

    /* 이전 실행의 소켓 파일 제거 */
    unlink(m_sock_path.c_str());

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_sock_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(m_srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[!] action_server: bind(%s) 실패: %s\n",
                m_sock_path.c_str(), strerror(errno));
        close(m_srv_fd); m_srv_fd = -1;
        return;
    }

    /* root 전용 권한 (소켓은 root로 실행 중이므로 의도된 설정) */
    chmod(m_sock_path.c_str(), 0600);

    if (listen(m_srv_fd, 8) < 0) {
        fprintf(stderr, "[!] action_server: listen() 실패: %s\n", strerror(errno));
        close(m_srv_fd); m_srv_fd = -1;
        return;
    }

    m_stop = false;
    m_thread = std::thread([this]{ accept_loop(); });
    fprintf(stderr, "[*] action_server: 소켓 준비 (%s)\n", m_sock_path.c_str());
}

void ActionServer::stop()
{
    m_stop = true;
    if (m_srv_fd >= 0) {
        shutdown(m_srv_fd, SHUT_RDWR);
        close(m_srv_fd);
        m_srv_fd = -1;
    }
    if (m_thread.joinable()) m_thread.join();
    unlink(m_sock_path.c_str());
}

void ActionServer::accept_loop()
{
    while (!m_stop) {
        int cli = accept(m_srv_fd, nullptr, nullptr);
        if (cli < 0) {
            if (!m_stop) perror("[!] action_server accept");
            break;
        }
        handle_client(cli);
        close(cli);
    }
}

void ActionServer::handle_client(int fd)
{
    /* 클라이언트로부터 한 줄 읽기 (최대 1KB) */
    char buf[1024] = {};
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;

    /* 개행 제거 */
    for (ssize_t i = 0; i < n; i++)
        if (buf[i] == '\n' || buf[i] == '\r') buf[i] = '\0';

    std::string resp = dispatch(buf);
    resp += "\n";
    send(fd, resp.c_str(), resp.size(), 0);
}

/* ── 명령 처리 ──────────────────────────────────────────────────────────── */

std::string ActionServer::dispatch(const std::string &line)
{
    std::string action = extract_str(line, "action");

    if (action == "ping") {
        return "{\"ok\":true,\"msg\":\"pong\"}";
    }

    if (action == "status") {
        if (!m_stats_fn)
            return "{\"ok\":false,\"msg\":\"stats unavailable\"}";
        AgentStats s = m_stats_fn();
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{\"ok\":true"
            ",\"procs\":%" PRIu64
            ",\"files\":%" PRIu64
            ",\"net\":%" PRIu64
            ",\"mem\":%" PRIu64
            ",\"dns\":%" PRIu64
            ",\"ns\":%" PRIu64
            ",\"total\":%" PRIu64 "}",
            s.n_proc, s.n_file, s.n_net, s.n_mem, s.n_dns, s.n_ns,
            s.n_proc + s.n_file + s.n_net + s.n_mem + s.n_dns + s.n_ns);
        return buf;
    }

    if (action == "kill") {
        long pid = extract_int(line, "pid");
        if (pid <= 1)
            return "{\"ok\":false,\"msg\":\"invalid pid\"}";

        /* sig 필드가 있으면 해당 시그널, 없으면 SIGKILL */
        long sig = extract_int(line, "sig");
        if (sig <= 0) sig = SIGKILL;

        if (kill((pid_t)pid, (int)sig) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                "{\"ok\":true,\"msg\":\"sent sig %ld to pid %ld\"}", sig, pid);
            fprintf(stderr, "[*] action: kill(pid=%ld, sig=%ld)\n", pid, sig);
            return buf;
        } else {
            char buf[128];
            snprintf(buf, sizeof(buf),
                "{\"ok\":false,\"msg\":\"%s\"}", strerror(errno));
            return buf;
        }
    }

    return "{\"ok\":false,\"msg\":\"unknown action\"}";
}

/* ── 최소 JSON 파서 ─────────────────────────────────────────────────────── */

std::string ActionServer::extract_str(const std::string &j, const char *key)
{
    std::string pat = std::string("\"") + key + "\":\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    size_t e = j.find('"', p);
    if (e == std::string::npos) return {};
    return j.substr(p, e - p);
}

long ActionServer::extract_int(const std::string &j, const char *key)
{
    std::string pat = std::string("\"") + key + "\":";
    size_t p = j.find(pat);
    if (p == std::string::npos) return -1;
    p += pat.size();
    /* 공백 스킵 */
    while (p < j.size() && j[p] == ' ') p++;
    char *end;
    long v = std::strtol(j.c_str() + p, &end, 10);
    return (end == j.c_str() + p) ? -1 : v;
}
