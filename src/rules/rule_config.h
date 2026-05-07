#pragma once
/*
 * rule_config.h - 외부 YAML 룰 설정 로더
 *
 * ┌─ 설계 ─────────────────────────────────────────────────────────────────┐
 * │                                                                         │
 * │  룰 데이터베이스(화이트리스트/블랙리스트/포트 목록)를 YAML 파일로       │
 * │  외부화하여 재컴파일 없이 변경 가능하게 한다.                          │
 * │                                                                         │
 * │  지원 YAML 서브셋:                                                      │
 * │    # 주석                                                               │
 * │    section_name:                                                        │
 * │      - value                                                            │
 * │                                                                         │
 * │  load() 실패 시 load_defaults() 로 폴백하는 것을 권장한다.             │
 * │                                                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
#include <cstdint>
#include <string>
#include <vector>

struct RuleConfig {
    /* ── 경로 목록 ─────────────────────────────────────────────────────── */
    std::vector<std::string> sensitive_paths;     /* R-001: 시스템 경로     */
    std::vector<std::string> log_paths;           /* R-002: 로그 경로       */
    std::vector<std::string> tmp_exec_paths;      /* R-003: 임시 경로       */

    /* ── 프로세스 comm 목록 ─────────────────────────────────────────────── */
    std::vector<std::string> shell_tools;         /* R-004: 공격 도구       */
    std::vector<std::string> interpreters;        /* R-005: 스크립트 인터프리터 */
    std::vector<std::string> shells;              /* R-011/R-012: 유닉스 셸 */
    std::vector<std::string> web_servers;         /* R-011: 웹 서버         */
    std::vector<std::string> db_servers;          /* R-012: DB 서버         */
    std::vector<std::string> pkg_manager_comms;   /* R-005/R-008 FP 억제    */

    /* ── 화이트리스트 ───────────────────────────────────────────────────── */
    std::vector<std::string> bind_whitelist;      /* R-007: 바인드 허용     */
    std::vector<std::string> sys_write_whitelist; /* R-001: 시스템 쓰기 허용 */
    std::vector<std::string> outbound_whitelist;  /* R-006: 아웃바운드 허용 */
    std::vector<std::string> setuid_whitelist;    /* R-015: setuid 허용     */
    std::vector<std::string> ptrace_whitelist;    /* R-014: ptrace 허용     */
    std::vector<std::string> memfd_whitelist;     /* R-017: memfd 허용      */
    std::vector<std::string> dns_whitelist;       /* R-018: DNS 허용        */
    std::vector<std::string> ns_escape_whitelist; /* R-024: NS 분리 허용    */

    /* ── DNS TLD 목록 ───────────────────────────────────────────────────── */
    std::vector<std::string> abused_tlds;         /* R-018c: 남용 TLD       */

    /* ── 포트 목록 ─────────────────────────────────────────────────────── */
    std::vector<uint16_t>    common_ports;        /* R-006: 일반 포트       */

    /* ── 위협 인텔리전스 설정 (스칼라 값) ──────────────────────────────── */
    std::string ip_feed_url    = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
    std::string domain_feed_url = "https://urlhaus.abuse.ch/downloads/text_online/";
    std::string hash_db_path;            /* 빈 문자열 = 해시 DB 미사용    */
    int         feed_update_hours = 6;   /* 피드 갱신 주기 (시간)         */

    /*
     * load(): YAML 파일에서 설정을 로드한다.
     * 파일을 열 수 없거나 알 수 없는 섹션이 있어도 파싱 가능한 항목은 처리한다.
     * 반환값: 파일을 성공적으로 열었으면 true, 열기 실패 시 false.
     */
    bool load(const std::string &path);

    /* load_defaults(): 코드에 내장된 기본값으로 모든 목록을 초기화한다. */
    void load_defaults();
};
