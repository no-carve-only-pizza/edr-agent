#pragma once
#include <string>
#include <unordered_set>
#include <shared_mutex>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <atomic>
#include <cstdint>

/*
 * FeedManager: 위협 인텔리전스 피드를 주기적으로 갱신하고
 * 이벤트 핸들러에서 동시에 조회할 수 있는 스레드 안전 클래스.
 *
 * 지원 피드:
 *   - Feodo Tracker IP 블록리스트 (R-025: 알려진 C2 IP 연결)
 *   - URLhaus 악성 도메인 피드   (R-026: 악성 도메인 DNS 조회)
 *
 * 설계:
 *   - 이벤트 핸들러(빈번) → shared_lock (다중 동시 읽기 허용)
 *   - 백그라운드 갱신 스레드 → unique_lock (단일 쓰기)
 *   - 초기 로드도 백그라운드에서 비동기 실행 (메인 스레드 블록 없음)
 */
class FeedManager {
public:
    /* ip_url: Feodo Tracker 텍스트 블록리스트 URL
     * domain_url: URLhaus 텍스트 피드 URL
     * update_hours: 갱신 주기 (시간) */
    FeedManager(std::string ip_url,
                std::string domain_url,
                int update_hours = 6);
    ~FeedManager();

    /* 백그라운드 갱신 스레드 시작 (main() 초기화 후 호출) */
    void start();
    void stop();

    /* IPv4 주소(네트워크 바이트 오더, uint32_t)가 C2 목록에 있는지 검사 */
    bool is_c2_ip4(uint32_t ip_net) const;

    /* 도메인 또는 그 부모 도메인이 악성 목록에 있는지 검사.
     * 예: 피드에 "evil.com" → query "sub.evil.com" → true */
    bool is_malicious_domain(const char *qname) const;

    /* 현재 로드된 항목 수 (디버깅/통계용) */
    size_t ip_count()     const;
    size_t domain_count() const;

private:
    void worker_loop();
    void fetch_once();

    /* libcurl로 URL을 문자열로 가져옴. 실패 시 빈 문자열 반환. */
    static std::string curl_get(const std::string &url);

    /* 텍스트 블록리스트 파싱 */
    static std::unordered_set<uint32_t>     parse_ip_list(const std::string &body);
    static std::unordered_set<std::string>  parse_domain_list(const std::string &body);

    /* 도트 표기법 IPv4 문자열 → uint32_t (네트워크 바이트 오더) */
    static bool parse_ipv4(const char *s, uint32_t &out);

    std::string m_ip_url;
    std::string m_domain_url;
    int         m_update_hours;

    mutable std::shared_mutex              m_mtx;
    std::unordered_set<uint32_t>           m_c2_ips;
    std::unordered_set<std::string>        m_mal_domains;

    std::thread             m_worker;
    std::mutex              m_cv_mtx;
    std::condition_variable m_cv;
    std::atomic<bool>       m_stop{false};
};
