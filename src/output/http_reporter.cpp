/*
 * http_reporter.cpp - libcurl 기반 HTTP NDJSON 리포터
 *
 * libcurl easy interface 사용:
 *   curl_easy_init()     : CURL 핸들 생성 (세션 상태 저장)
 *   curl_easy_setopt()   : 옵션 설정 (URL, POST 데이터, 헤더 등)
 *   curl_easy_perform()  : 실제 HTTP 요청 실행 (동기)
 *   curl_easy_cleanup()  : 핸들 해제
 *
 * curl_slist 는 커스텀 헤더 목록을 위한 링크드 리스트.
 * curl_slist_append() 로 헤더를 추가하고
 * curl_slist_free_all() 로 해제한다.
 *
 * 성능 고려:
 *   curl_easy_perform() 은 호출마다 TCP 연결을 맺는다.
 *   프로덕션에서는 keep-alive 또는 curl_multi_* 인터페이스를 사용해야 한다.
 *   이 PoC 에서는 단순성을 위해 동기 방식을 사용한다.
 */
#include "output/http_reporter.h"
#include <curl/curl.h>
#include <cstdio>

HttpReporter::HttpReporter(std::string endpoint, std::string token,
                            bool alerts_only)
    : endpoint_(std::move(endpoint))
    , token_(std::move(token))
    , alerts_only_(alerts_only)
{
    if (!endpoint_.empty()) {
        /* curl_global_init() 은 프로세스 당 한 번만 호출해야 한다.
         * CURL_GLOBAL_DEFAULT: SSL + Win32 소켓 초기화 포함. */
        curl_global_init(CURL_GLOBAL_DEFAULT);
        fprintf(stderr, "[HTTP] 리포터 활성화: %s%s\n",
                endpoint_.c_str(),
                alerts_only_ ? " (alerts only)" : "");
    }
}

HttpReporter::~HttpReporter()
{
    flush();
    if (!endpoint_.empty())
        curl_global_cleanup();
}

void HttpReporter::submit(const std::string &json_line, bool has_alert)
{
    if (!active()) return;
    if (alerts_only_ && !has_alert) return;

    buf_.push_back(json_line);

    if ((int)buf_.size() >= FLUSH_SIZE)
        flush();
}

void HttpReporter::flush()
{
    if (buf_.empty()) return;
    post_batch();
    buf_.clear();
}

void HttpReporter::post_batch()
{
    /*
     * 버퍼의 모든 JSON 줄을 개행(\n)으로 연결해 NDJSON 바디를 구성한다.
     * 예:
     *   {"type":"exec","pid":1234,...}\n
     *   {"type":"net_connect","pid":5678,...}\n
     */
    std::string body;
    body.reserve(buf_.size() * 256);
    for (const auto &line : buf_) {
        body += line;
        body += '\n';
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[HTTP] curl_easy_init 실패\n");
        return;
    }

    /* ── curl 옵션 설정 ────────────────────────────────────────────────── */

    curl_easy_setopt(curl, CURLOPT_URL, endpoint_.c_str());

    /*
     * CURLOPT_POSTFIELDS: POST 바디 설정.
     * 문자열 포인터를 전달하면 curl 이 내부적으로 strlen() 으로 크기를 계산.
     * 바이너리 데이터나 NUL 포함 데이터는 CURLOPT_POSTFIELDSIZE 를 함께 써야 한다.
     */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());

    /* 응답 본문을 버리는 콜백 (stdout 오염 방지) */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);

    /* 연결 타임아웃: 2초, 전송 타임아웃: 5초 */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        5L);

    /* ── 커스텀 헤더 ───────────────────────────────────────────────────── */

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");

    if (!token_.empty()) {
        std::string auth = "Authorization: Bearer " + token_;
        headers = curl_slist_append(headers, auth.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* ── 실행 ──────────────────────────────────────────────────────────── */

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "[HTTP] POST 실패 (%zu events): %s\n",
                buf_.size(), curl_easy_strerror(res));
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code < 200 || http_code >= 300)
            fprintf(stderr, "[HTTP] 서버 응답 %ld\n", http_code);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}
