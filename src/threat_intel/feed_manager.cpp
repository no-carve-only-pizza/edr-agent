#include "threat_intel/feed_manager.h"
#include <curl/curl.h>
#include <arpa/inet.h>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <chrono>

/* ── libcurl write callback ─────────────────────────────────────────────── */

static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    auto *buf = static_cast<std::string *>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

/* ── FeedManager ────────────────────────────────────────────────────────── */

FeedManager::FeedManager(std::string ip_url,
                         std::string domain_url,
                         int update_hours)
    : m_ip_url(std::move(ip_url))
    , m_domain_url(std::move(domain_url))
    , m_update_hours(update_hours)
{}

FeedManager::~FeedManager() { stop(); }

void FeedManager::start()
{
    m_stop = false;
    m_worker = std::thread([this]{ worker_loop(); });
}

void FeedManager::stop()
{
    m_stop = true;
    m_cv.notify_all();
    if (m_worker.joinable())
        m_worker.join();
}

void FeedManager::worker_loop()
{
    fetch_once();

    const auto interval = std::chrono::hours(m_update_hours);
    while (!m_stop) {
        std::unique_lock<std::mutex> lk(m_cv_mtx);
        m_cv.wait_for(lk, interval, [this]{ return m_stop.load(); });
        if (!m_stop)
            fetch_once();
    }
}

void FeedManager::fetch_once()
{
    /* IP 피드 (Feodo Tracker) */
    std::string ip_body = curl_get(m_ip_url);
    auto new_ips = ip_body.empty()
                 ? std::unordered_set<uint32_t>{}
                 : parse_ip_list(ip_body);

    /* 도메인 피드 (URLhaus) */
    std::string dom_body = curl_get(m_domain_url);
    auto new_domains = dom_body.empty()
                     ? std::unordered_set<std::string>{}
                     : parse_domain_list(dom_body);

    /* 쓰기 잠금으로 원자적 교체 */
    std::unique_lock<std::shared_mutex> lk(m_mtx);
    m_c2_ips     = std::move(new_ips);
    m_mal_domains = std::move(new_domains);
}

/* ── 조회 API ───────────────────────────────────────────────────────────── */

bool FeedManager::is_c2_ip4(uint32_t ip_net) const
{
    std::shared_lock<std::shared_mutex> lk(m_mtx);
    return m_c2_ips.count(ip_net) > 0;
}

bool FeedManager::is_malicious_domain(const char *qname) const
{
    if (!qname || !*qname) return false;

    std::string q(qname);
    /* 도트로 분리해 가며 suffix 매칭:
     * "a.b.evil.com" → "a.b.evil.com", "b.evil.com", "evil.com", "com" */
    std::shared_lock<std::shared_mutex> lk(m_mtx);
    size_t pos = 0;
    while (pos < q.size()) {
        std::string candidate = q.substr(pos);
        if (m_mal_domains.count(candidate))
            return true;
        size_t dot = q.find('.', pos);
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    return false;
}

size_t FeedManager::ip_count() const
{
    std::shared_lock<std::shared_mutex> lk(m_mtx);
    return m_c2_ips.size();
}

size_t FeedManager::domain_count() const
{
    std::shared_lock<std::shared_mutex> lk(m_mtx);
    return m_mal_domains.size();
}

/* ── libcurl HTTP GET ───────────────────────────────────────────────────── */

std::string FeedManager::curl_get(const std::string &url)
{
    CURL *curl = curl_easy_init();
    if (!curl) return "";

    std::string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "edr-agent/1.0");
    /* TLS 검증 유지 — 위협 인텔 피드는 반드시 신뢰된 서버에서만 받음 */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) return "";
    return body;
}

/* ── 파싱 헬퍼 ──────────────────────────────────────────────────────────── */

bool FeedManager::parse_ipv4(const char *s, uint32_t &out)
{
    struct in_addr addr{};
    if (inet_pton(AF_INET, s, &addr) != 1) return false;
    out = addr.s_addr; /* 네트워크 바이트 오더 */
    return true;
}

/*
 * Feodo Tracker 포맷 예시:
 *   # 주석
 *   185.220.101.45
 *   45.33.32.156
 */
std::unordered_set<uint32_t> FeedManager::parse_ip_list(const std::string &body)
{
    std::unordered_set<uint32_t> result;
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '#') continue;
        /* 앞뒤 공백 제거 */
        size_t a = line.find_first_not_of(" \t\r");
        size_t b = line.find_last_not_of(" \t\r");
        if (a == std::string::npos) continue;
        std::string token = line.substr(a, b - a + 1);
        /* "IP,port" 형식도 허용 */
        size_t comma = token.find(',');
        if (comma != std::string::npos) token = token.substr(0, comma);
        uint32_t ip;
        if (parse_ipv4(token.c_str(), ip))
            result.insert(ip);
    }
    return result;
}

/*
 * URLhaus text_online 포맷 예시:
 *   # 주석
 *   http://evil.com/path
 *   https://bad.example.ru/malware.exe
 *
 * 도메인만 추출해 저장한다 (프로토콜·경로 제거).
 */
std::unordered_set<std::string> FeedManager::parse_domain_list(const std::string &body)
{
    std::unordered_set<std::string> result;
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '#') continue;
        /* 앞뒤 공백 */
        size_t a = line.find_first_not_of(" \t\r");
        if (a == std::string::npos) continue;
        std::string url = line.substr(a);

        /* "scheme://" 제거 */
        size_t slashslash = url.find("://");
        if (slashslash != std::string::npos)
            url = url.substr(slashslash + 3);

        /* 경로 이후 제거 */
        size_t slash = url.find('/');
        if (slash != std::string::npos) url = url.substr(0, slash);

        /* "host:port" 형식에서 포트 제거 */
        size_t colon = url.find(':');
        if (colon != std::string::npos) url = url.substr(0, colon);

        if (!url.empty())
            result.insert(url);
    }
    return result;
}
