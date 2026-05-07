#pragma once
/*
 * http_reporter.h - 이벤트 JSON 을 HTTP 엔드포인트로 전송
 *
 * 동작 방식:
 *   submit() 으로 JSON 줄을 버퍼에 쌓고,
 *   버퍼가 FLUSH_SIZE 에 도달하거나 flush() 가 명시적으로 호출되면
 *   libcurl 을 통해 HTTP POST 로 전송한다 (NDJSON 형식).
 *
 * NDJSON (Newline-Delimited JSON):
 *   Content-Type: application/x-ndjson
 *   한 줄 = 하나의 완결된 JSON 오브젝트.
 *   스트리밍 파싱에 유리하고, 백엔드에서 Elasticsearch / Loki / 커스텀
 *   ingestor 에 직접 연결하기 좋은 형식이다.
 */
#include <string>
#include <vector>

class HttpReporter {
public:
    /* endpoint: "http://host:port/path" 형식.
     * token:    Authorization: Bearer <token> 헤더값 (빈 문자열이면 생략).
     * alerts_only: true 면 alerts 배열이 비어 있는 이벤트는 전송 생략.
     */
    HttpReporter(std::string endpoint, std::string token,
                 bool alerts_only = false);
    ~HttpReporter();

    /* 비활성(endpoint 없음)이면 즉시 반환 */
    bool active() const { return !endpoint_.empty(); }

    /* JSON 줄 하나를 버퍼에 추가. FLUSH_SIZE 초과 시 자동 flush. */
    void submit(const std::string &json_line, bool has_alert);

    /* 버퍼 내용을 즉시 전송 */
    void flush();

private:
    static constexpr int FLUSH_SIZE = 20; /* 이벤트 N 개마다 자동 전송 */

    std::string endpoint_;
    std::string token_;
    bool        alerts_only_;
    std::vector<std::string> buf_;

    /* libcurl write 콜백: 응답 본문을 무시하기 위한 더미 */
    static size_t discard_cb(void *, size_t, size_t n, void *) { return n; }

    void post_batch();
};
