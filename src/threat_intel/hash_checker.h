#pragma once
#include <string>
#include <unordered_set>

/*
 * HashChecker: 알려진 악성 파일 해시(SHA-256) DB를 메모리에 로드하고
 * 실행 파일의 해시를 즉시 조회한다.
 *
 * 피드 파일 포맷 (config/known_hashes.txt):
 *   # 주석
 *   <64자리 소문자 SHA-256 hex>
 *
 * R-027: exec 이벤트에서 파일 경로를 SHA-256 해시 → DB 조회.
 * 정탐 시 severity = critical.
 */
class HashChecker {
public:
    /* hash_db_path: known_hashes.txt 경로. 빈 문자열이면 DB 없이 초기화. */
    explicit HashChecker(const std::string &hash_db_path = "");

    /* 파일 경로를 해시 후 DB 조회. 악성이면 true. */
    bool check_file(const char *path) const;

    /* 이미 계산된 해시 문자열(64자)로 직접 조회. */
    bool check_hash(const std::string &hex) const;

    /* DB 로드 (재로드 시 기존 내용 대체) */
    bool load(const std::string &path);

    size_t count() const { return m_hashes.size(); }

private:
    std::unordered_set<std::string> m_hashes;
};
