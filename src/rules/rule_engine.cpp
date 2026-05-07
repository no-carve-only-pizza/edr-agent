/*
 * rule_engine.cpp - EDR 탐지 룰 데이터베이스 & 매칭 로직
 *
 * ┌─ 룰 매칭 흐름 ─────────────────────────────────────────────────────────┐
 * │                                                                         │
 * │  커널 이벤트                                                            │
 * │  (process_event / file_event / net_event)                              │
 * │          │                                                              │
 * │          ▼                                                              │
 * │  match_rules(e) : 이벤트 타입에 맞는 룰 테이블 순차 검사               │
 * │          │                                                              │
 * │          ▼                                                              │
 * │  helpers: comm_in() / path_has_prefix() / port_in()                   │
 * │    → 문자열 비교(O(k))로 조건 평가 (k = 룰 수)                        │
 * │          │                                                              │
 * │          ▼                                                              │
 * │  std::vector<RuleMatch> 반환 (매칭된 룰만 포함)                        │
 * │                                                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * 확장 방향:
 *   - 룰을 JSON 파일로 외부화: nlohmann/json 또는 simdjson 파싱 추가
 *   - 정규식 매칭: std::regex (성능 민감하면 re2 라이브러리)
 *   - 화이트리스트: known-good 프로세스/경로 목록으로 FP 억제
 */
#include "rules/rule_engine.h"
#include <arpa/inet.h>  /* ntohs() */
#include <cstring>

/* ── 매칭 헬퍼 ─────────────────────────────────────────────────────────── */

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* null-terminated 문자열 배열에서 comm 검색 (exact match) */
static bool comm_in(const char *comm, const char * const *list)
{
    for (; *list; ++list)
        if (strcmp(comm, *list) == 0) return true;
    return false;
}

/* null-terminated prefix 배열 중 하나로 시작하는지 검사 */
static bool path_has_prefix(const char *path, const char * const *list)
{
    for (; *list; ++list)
        if (starts_with(path, *list)) return true;
    return false;
}

/*
 * null-terminated 포트 배열에서 port 검색.
 * port 는 이미 호스트 바이트 오더(ntohs 변환 후)여야 한다.
 */
static bool port_in(uint16_t port, const uint16_t *list)
{
    for (; *list; ++list)
        if (*list == port) return true;
    return false;
}

/* ── 룰 데이터베이스 ────────────────────────────────────────────────────── */

/*
 * R-001 기준: 공격자가 지속성(Persistence)을 위해 수정하는 전형적 경로.
 * /etc/cron*, /etc/passwd, /etc/shadow, /etc/ld.so.preload 등.
 */
static const char *SENSITIVE_PATHS[] = {
    "/etc/", "/boot/", "/bin/", "/sbin/",
    "/usr/bin/", "/usr/sbin/",
    "/lib/", "/lib64/", "/usr/lib/",
    nullptr
};

/* R-002: 공격자가 증거 인멸을 위해 지우는 경로 */
static const char *LOG_PATHS[] = {
    "/var/log/",
    "/run/log/",
    nullptr
};

/* R-003: 메모리에서 실행된 드로퍼가 /tmp 에 쓰고 실행하는 패턴 */
static const char *TMP_EXEC_PATHS[] = {
    "/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/",
    nullptr
};

/*
 * R-004: 공격자가 자주 쓰는 리버스셸/C2/정찰 도구.
 * basename 만 비교하므로 /usr/bin/nc 와 nc 모두 매칭.
 */
static const char *SHELL_TOOLS[] = {
    "nc", "ncat", "netcat", "socat",
    "nmap", "masscan",
    "msfconsole", "msfvenom",
    "empire", "covenant",
    nullptr
};

/*
 * R-005: 스크립트 인터프리터 직접 실행.
 * 정상적인 환경에서는 스크립트 파일을 인자로 받지만,
 * 공격자는 종종 -c 'exec(...)' 형태로 인라인 페이로드를 실행한다.
 * → sys_enter_execve 의 argv 파싱은 마일스톤 5+ 에서 추가.
 */
static const char *INTERPRETERS[] = {
    "python", "python2", "python3",
    "perl", "ruby", "php", "lua",
    "node", "nodejs",
    nullptr
};

/*
 * R-006: 정상 트래픽에서 흔한 포트. 이 외의 포트로의 연결은 의심.
 * 실제 환경에서는 조직의 허용 포트 목록으로 대체해야 한다.
 * 마지막 0 은 sentinel (배열 끝 표시).
 */
static const uint16_t COMMON_PORTS[] = {
    21, 22, 25, 53, 80, 110, 143,
    443, 465, 587, 993, 995,
    3306, 5432, 6379, 27017,
    8080, 8443, 9200,
    0  /* sentinel */
};

/* ── 이벤트별 룰 매칭 구현 ──────────────────────────────────────────────── */

std::vector<RuleMatch> match_rules(const process_event &e)
{
    std::vector<RuleMatch> hits;

    /* R-003: 임시 디렉터리에서 실행 */
    if (path_has_prefix(e.filename, TMP_EXEC_PATHS))
        hits.push_back({"R-003", "/tmp 경로 실행 (드로퍼 의심)", "high"});

    /* R-004: 리버스셸/공격 도구 실행 */
    if (comm_in(e.comm, SHELL_TOOLS))
        hits.push_back({"R-004", "리버스셸/스캔 도구 실행", "critical"});

    /* R-005: 스크립트 인터프리터 실행 */
    if (comm_in(e.comm, INTERPRETERS))
        hits.push_back({"R-005", "스크립트 인터프리터 실행", "medium"});

    /* R-008: root 권한으로 인터프리터 실행 (권한 상승 후 페이로드 실행 의심) */
    if (e.uid == 0 && comm_in(e.comm, INTERPRETERS))
        hits.push_back({"R-008", "root 권한 인터프리터 실행", "critical"});

    return hits;
}

std::vector<RuleMatch> match_rules(const file_event &e)
{
    std::vector<RuleMatch> hits;

    if (e.type == EVENT_FILE_WRITE || e.type == EVENT_FILE_RENAME) {
        /* R-001: 시스템 바이너리/설정 파일 수정 */
        if (path_has_prefix(e.path, SENSITIVE_PATHS))
            hits.push_back({"R-001", "시스템 경로 파일 수정", "high"});
    }

    if (e.type == EVENT_FILE_DELETE) {
        /* R-002: 로그 파일 삭제 (증거 인멸) */
        if (path_has_prefix(e.path, LOG_PATHS))
            hits.push_back({"R-002", "로그 파일 삭제 (증거 인멸 의심)", "high"});
    }

    if (e.type == EVENT_FILE_RENAME) {
        /*
         * R-009: /tmp 에서 시스템 경로로 rename.
         * TOCTOU + rename 원자성을 악용한 권한 상승 기법:
         *   1) /tmp/evil 에 악성 파일 생성
         *   2) renameat2(RENAME_EXCHANGE) 로 /usr/bin/sudo 와 원자 교체
         */
        if (path_has_prefix(e.path, TMP_EXEC_PATHS) &&
            path_has_prefix(e.path2, SENSITIVE_PATHS))
            hits.push_back({"R-009", "/tmp → 시스템 경로 rename (TOCTOU 의심)", "critical"});
    }

    return hits;
}

std::vector<RuleMatch> match_rules(const net_event &e)
{
    std::vector<RuleMatch> hits;
    uint16_t port = ntohs(e.dport);

    if (e.type == EVENT_NET_CONNECT && port != 0) {
        /* R-006: 비표준 포트 아웃바운드 연결 */
        if (!port_in(port, COMMON_PORTS))
            hits.push_back({"R-006", "비표준 포트 아웃바운드 연결", "medium"});
    }

    if (e.type == EVENT_NET_BIND && port != 0) {
        /* R-007: 서버 포트 바인드 (백도어 리스너 의심) */
        hits.push_back({"R-007", "서버 포트 바인드", "low"});
    }

    return hits;
}

/* ── 유틸리티 ───────────────────────────────────────────────────────────── */

const char *severity_color(const char *severity)
{
    /* ANSI 이스케이프: \033[<code>m
     *   1  = bold
     *   31 = red, 33 = yellow, 34 = blue, 35 = magenta, 0 = reset
     */
    if (strcmp(severity, "critical") == 0) return "\033[1;35m"; /* 굵은 자홍 */
    if (strcmp(severity, "high")     == 0) return "\033[1;31m"; /* 굵은 빨강 */
    if (strcmp(severity, "medium")   == 0) return "\033[1;33m"; /* 굵은 노랑 */
    if (strcmp(severity, "low")      == 0) return "\033[1;34m"; /* 굵은 파랑 */
    return "\033[0m";
}
