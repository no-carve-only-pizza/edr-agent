#pragma once
/*
 * action_server.h - Unix 도메인 소켓 기반 능동 대응(Active Response) 수신부
 *
 * 외부 관리 도구(edr-ctl)가 JSON 명령을 소켓으로 전송하면
 * 에이전트가 즉시 실행한다.
 *
 * 프로토콜: 줄 구분 JSON (line-delimited JSON)
 *
 *   요청: {"action":"kill","pid":1234}
 *   응답: {"ok":true,"msg":"killed 1234"}
 *
 *   요청: {"action":"kill","pid":1234,"sig":15}
 *   응답: {"ok":true,"msg":"sent sig 15 to 1234"}
 *
 *   요청: {"action":"status"}
 *   응답: {"ok":true,"events":12345,"procs":532,"files":1823,...}
 *
 *   요청: {"action":"ping"}
 *   응답: {"ok":true,"msg":"pong"}
 *
 * 소켓 경로: /run/edr-agent.sock (기본값, --socket 옵션으로 변경 가능)
 * 소켓 권한: 0600 (root 전용)
 */
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

struct AgentStats {
    uint64_t n_proc;
    uint64_t n_file;
    uint64_t n_net;
    uint64_t n_mem;
    uint64_t n_dns;
    uint64_t n_ns;
};

class ActionServer {
public:
    static constexpr const char *DEFAULT_SOCK = "/run/edr-agent.sock";

    explicit ActionServer(std::string sock_path = DEFAULT_SOCK);
    ~ActionServer();

    /* stats_fn: 상태 조회 시 호출할 콜백 (main 스레드 데이터를 읽음) */
    void set_stats_fn(std::function<AgentStats()> fn) { m_stats_fn = std::move(fn); }

    void start();
    void stop();

private:
    void accept_loop();
    void handle_client(int fd);
    std::string dispatch(const std::string &line);

    /* 최소 JSON 파싱 헬퍼 */
    static std::string extract_str(const std::string &j, const char *key);
    static long        extract_int(const std::string &j, const char *key);

    std::string                    m_sock_path;
    int                            m_srv_fd = -1;
    std::thread                    m_thread;
    std::atomic<bool>              m_stop{false};
    std::function<AgentStats()>    m_stats_fn;
};
