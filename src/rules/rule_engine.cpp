/*
 * rule_engine.cpp - EDR 탐지 룰 데이터베이스 & 매칭 로직
 *
 * ┌─ 룰 매칭 흐름 ─────────────────────────────────────────────────────────┐
 * │                                                                         │
 * │  커널 이벤트                                                            │
 * │  (process_event / file_event / net_event / ...)                        │
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
 * 룰 목록(벡터)은 init_rules(cfg) 로 외부 YAML 또는 내장 기본값으로 초기화된다.
 * init_rules() 를 호출하지 않으면 모든 목록이 비어 탐지가 동작하지 않는다.
 */
#include "rules/rule_engine.h"
#include "rules/rule_config.h"
#include <algorithm>    /* std::remove_if */
#include <arpa/inet.h>  /* ntohs() */
#include <cstring>

/* ── 매칭 헬퍼 ─────────────────────────────────────────────────────────── */

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/*
 * get_argv_n: NUL 구분 argv 버퍼에서 n번째 인자 포인터 반환.
 *
 * process_event.argv 는 /proc/PID/cmdline 과 동일한 형식:
 *   "argv0\0argv1\0argv2\0..."
 *
 * 반환값: n번째 인자 시작 주소, 범위 초과 시 nullptr.
 */
static const char *get_argv_n(const char *buf, __u32 n)
{
    size_t off = 0;
    for (__u32 i = 0; i < n; i++) {
        while (off < MAX_ARGV_LEN && buf[off] != '\0') off++;
        off++; /* NUL 건너뜀 */
        if (off >= MAX_ARGV_LEN) return nullptr;
    }
    return (off < MAX_ARGV_LEN) ? buf + off : nullptr;
}

/* std::vector<std::string> 에서 comm 검색 (exact match) */
static bool comm_in(const char *comm, const std::vector<std::string> &list)
{
    for (const auto &s : list)
        if (strcmp(comm, s.c_str()) == 0) return true;
    return false;
}

/* std::vector<std::string> 중 하나로 시작하는지 검사 */
static bool path_has_prefix(const char *path, const std::vector<std::string> &list)
{
    for (const auto &s : list)
        if (starts_with(path, s.c_str())) return true;
    return false;
}

/*
 * std::vector<uint16_t> 에서 port 검색.
 * port 는 이미 호스트 바이트 오더(ntohs 변환 후)여야 한다.
 */
static bool port_in(uint16_t port, const std::vector<uint16_t> &list)
{
    for (uint16_t p : list)
        if (p == port) return true;
    return false;
}

/* ── 룰 데이터베이스 (벡터) ─────────────────────────────────────────────── */

/*
 * 모든 목록은 init_rules() 에서 채워진다.
 * 선언만 해두고 초기화는 하지 않는다 → 빈 벡터 = "탐지 없음" (안전한 기본 상태).
 */
static std::vector<std::string> SENSITIVE_PATHS;
static std::vector<std::string> LOG_PATHS;
static std::vector<std::string> TMP_EXEC_PATHS;
static std::vector<std::string> SHELL_TOOLS;
static std::vector<std::string> INTERPRETERS;
static std::vector<std::string> SHELLS;
static std::vector<std::string> WEB_SERVERS;
static std::vector<std::string> DB_SERVERS;
static std::vector<std::string> PKG_MANAGER_COMMS;
static std::vector<uint16_t>    COMMON_PORTS;

/* ── 화이트리스트 벡터 ──────────────────────────────────────────────────── */

static std::vector<std::string> BIND_WHITELIST;
static std::vector<std::string> SYS_WRITE_WHITELIST;
static std::vector<std::string> OUTBOUND_WHITELIST;
static std::vector<std::string> SETUID_WHITELIST;
static std::vector<std::string> PTRACE_WHITELIST;
static std::vector<std::string> MEMFD_WHITELIST;
static std::vector<std::string> DNS_WHITELIST;
static std::vector<std::string> NS_ESCAPE_WHITELIST;
static std::vector<std::string> ABUSED_TLDS;

/* ── 룰 초기화 ─────────────────────────────────────────────────────────── */

void init_rules(const RuleConfig &cfg)
{
    SENSITIVE_PATHS     = cfg.sensitive_paths;
    LOG_PATHS           = cfg.log_paths;
    TMP_EXEC_PATHS      = cfg.tmp_exec_paths;
    SHELL_TOOLS         = cfg.shell_tools;
    INTERPRETERS        = cfg.interpreters;
    SHELLS              = cfg.shells;
    WEB_SERVERS         = cfg.web_servers;
    DB_SERVERS          = cfg.db_servers;
    PKG_MANAGER_COMMS   = cfg.pkg_manager_comms;
    COMMON_PORTS        = cfg.common_ports;
    BIND_WHITELIST      = cfg.bind_whitelist;
    SYS_WRITE_WHITELIST = cfg.sys_write_whitelist;
    OUTBOUND_WHITELIST  = cfg.outbound_whitelist;
    SETUID_WHITELIST    = cfg.setuid_whitelist;
    PTRACE_WHITELIST    = cfg.ptrace_whitelist;
    MEMFD_WHITELIST     = cfg.memfd_whitelist;
    DNS_WHITELIST       = cfg.dns_whitelist;
    NS_ESCAPE_WHITELIST = cfg.ns_escape_whitelist;
    ABUSED_TLDS         = cfg.abused_tlds;
}

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

    /*
     * R-013: LD_PRELOAD 환경변수 인젝션.
     *
     * LD_PRELOAD 는 동적 링커가 다른 공유 라이브러리보다 먼저 지정된 .so 를 로드한다.
     * 공격자는 이를 이용해 libc 함수(open, read, readdir 등)를 후킹하거나
     * 정상 바이너리 실행 시 악성 코드를 함께 실행한다.
     */
    if (e.has_ld_preload)
        hits.push_back({"R-013", "LD_PRELOAD 환경변수 인젝션 의심", "high"});

    /*
     * R-015: setuid 바이너리 실행 (권한 상승).
     *
     * uid(real) ≠ euid(effective) 이면 setuid 비트가 설정된 바이너리다.
     * 알려진 정상 setuid 바이너리(sudo, ping 등)는 화이트리스트로 제외.
     */
    if (e.uid != e.euid && !comm_in(e.comm, SETUID_WHITELIST))
        hits.push_back({"R-015", "예상치 못한 setuid 실행 (권한 상승 의심)", "critical"});

    /*
     * R-010: 인터프리터 + -c 플래그 (인라인 페이로드 실행).
     *
     * python3 -c "import os; ..." / perl -e '...' 패턴.
     * 파일리스(fileless) 공격의 핵심 지표.
     */
    if (comm_in(e.comm, INTERPRETERS) && e.argc >= 2) {
        const char *arg1 = get_argv_n(e.argv, 1);
        if (arg1 && (strcmp(arg1, "-c") == 0 || strcmp(arg1, "-e") == 0))
            hits.push_back({"R-010", "인터프리터 인라인 페이로드 (-c/-e 플래그)", "high"});
    }

    return hits;
}

std::vector<RuleMatch> match_rules(const file_event &e)
{
    std::vector<RuleMatch> hits;

    if (e.type == EVENT_FILE_WRITE || e.type == EVENT_FILE_RENAME) {
        /*
         * R-001: 시스템 바이너리/설정 파일 수정.
         * SYS_WRITE_WHITELIST: apt/dpkg 등 패키지 관리자의 합법적 설치 동작 제외.
         */
        if (path_has_prefix(e.path, SENSITIVE_PATHS) &&
            !comm_in(e.comm, SYS_WRITE_WHITELIST))
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
         * TOCTOU + rename 원자성을 악용한 권한 상승 기법.
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
        /*
         * R-006: 비표준 포트 아웃바운드 연결.
         * OUTBOUND_WHITELIST: curl/wget/apt 등 도구는 사용자가 의도적으로
         * 지정한 포트를 사용하므로 제외한다.
         */
        if (!port_in(port, COMMON_PORTS) && !comm_in(e.comm, OUTBOUND_WHITELIST))
            hits.push_back({"R-006", "비표준 포트 아웃바운드 연결", "medium"});
    }

    if (e.type == EVENT_NET_BIND && port != 0) {
        /*
         * R-007: 서버 포트 바인드 (백도어 리스너 의심).
         * BIND_WHITELIST: 합법적인 서버 프로세스(sshd, nginx, mysqld 등) 제외.
         */
        if (!comm_in(e.comm, BIND_WHITELIST))
            hits.push_back({"R-007", "서버 포트 바인드 (알 수 없는 프로세스)", "low"});
    }

    return hits;
}

/* ── 프로세스 트리 기반 룰 ──────────────────────────────────────────────── */

std::vector<RuleMatch> match_rules(const process_event &e, const char *parent_comm)
{
    /* 기존 단독 이벤트 룰 먼저 수집 */
    auto hits = match_rules(e);

    /*
     * R-005/R-008 FP 억제: 패키지 관리자·빌드 도구가 부모인 경우.
     *
     * apt install python3-package → postinst 스크립트에서 python3 호출
     * pip install xxx             → setup.py 빌드 중 python3 호출
     */
    if (parent_comm && comm_in(parent_comm, PKG_MANAGER_COMMS)) {
        hits.erase(
            std::remove_if(hits.begin(), hits.end(),
                [](const RuleMatch &m) {
                    return strcmp(m.id, "R-005") == 0 ||
                           strcmp(m.id, "R-008") == 0;
                }),
            hits.end());
    }

    if (!parent_comm || parent_comm[0] == '\0')
        return hits;

    bool child_is_shell = comm_in(e.comm, SHELLS);
    bool child_is_interp = comm_in(e.comm, INTERPRETERS);

    /*
     * R-011: 웹 서버 자식 프로세스가 셸 또는 인터프리터를 실행.
     * nginx → bash  ← 웹셸이 system() / proc_open() 호출
     */
    if (comm_in(parent_comm, WEB_SERVERS) && (child_is_shell || child_is_interp))
        hits.push_back({"R-011", "웹 서버 자식 셸 실행 (웹셸/RCE 의심)", "critical"});

    /*
     * R-012: DB 서버 자식 프로세스가 셸 또는 인터프리터를 실행.
     * postgres → sh : COPY TO PROGRAM 을 통한 OS 명령 실행
     */
    if (comm_in(parent_comm, DB_SERVERS) && (child_is_shell || child_is_interp))
        hits.push_back({"R-012", "DB 서버 자식 셸 실행 (SQLi RCE 의심)", "critical"});

    return hits;
}

std::vector<RuleMatch> match_rules(const ptrace_event &e)
{
    std::vector<RuleMatch> hits;

    /*
     * R-014: ptrace ATTACH - 프로세스 추적/인젝션 시도.
     *
     * 합법적 사용(gdb, strace 등)은 PTRACE_WHITELIST 로 억제.
     */
    if (!comm_in(e.comm, PTRACE_WHITELIST))
        hits.push_back({"R-014", "ptrace ATTACH - 프로세스 추적/인젝션 의심", "high"});

    return hits;
}

std::vector<RuleMatch> match_rules(const memory_event &e)
{
    std::vector<RuleMatch> hits;

    /*
     * R-016: RWX 메모리 할당 감지.
     * PROT_EXEC(4) 와 PROT_WRITE(2) 가 동시에 설정된 메모리는
     * 쉘코드 삽입(JIT 스프레이 등)에 주로 사용된다.
     */
    if ((e.prot & 6) == 6)
        hits.push_back({"R-016", "RWX 메모리 할당 (JIT/쉘코드 의심)", "high"});

    return hits;
}

std::vector<RuleMatch> match_rules(const memfd_event &e)
{
    std::vector<RuleMatch> hits;

    if (comm_in(e.comm, MEMFD_WHITELIST))
        return hits; /* 알려진 JIT 런타임·시스템 소프트웨어 → 제외 */

    /*
     * R-017: memfd_create() 파일리스 공격 패턴.
     *
     * MFD_ALLOW_SEALING(0x2): 기록 후 메모리를 불변으로 밀봉 → 셸코드 완성 지표.
     * 이름이 빈 문자열(""): 추적 회피 의도.
     */
    bool sealing    = (e.flags & 0x2) != 0;
    bool empty_name = (e.name[0] == '\0');

    if (sealing || empty_name)
        hits.push_back({"R-017", "memfd_create 파일리스 실행 (셸코드 드로퍼 의심)", "critical"});
    else
        hits.push_back({"R-017", "memfd_create 익명 파일 생성 (파일리스 의심)", "high"});

    return hits;
}

/* ── DNS 룰 ─────────────────────────────────────────────────────────────── */

/*
 * max_label_len(): 도메인명의 레이블 중 가장 긴 것의 길이 반환.
 * DNS 터널링은 레이블 내에 데이터를 인코딩하므로 레이블 단위로 검사.
 */
static size_t max_label_len(const char *name)
{
    size_t max_len = 0, cur_len = 0;
    for (const char *p = name; *p; ++p) {
        if (*p == '.') {
            if (cur_len > max_len) max_len = cur_len;
            cur_len = 0;
        } else {
            cur_len++;
        }
    }
    if (cur_len > max_len) max_len = cur_len;
    return max_len;
}

/*
 * vowel_ratio(): 알파벳 중 모음(aeiou) 비율 반환 (0.0~1.0).
 *
 * DGA 도메인 휴리스틱: 정상 영어 단어의 모음 비율은 약 0.38.
 * DGA 생성 랜덤 문자열은 모음이 거의 없다 (ratio < 0.15).
 */
static float vowel_ratio(const char *name)
{
    int alpha = 0, vowels = 0;
    for (const char *p = name; *p && *p != '.'; ++p) {
        char c = *p | 0x20; /* 소문자 변환 */
        if (c >= 'a' && c <= 'z') {
            alpha++;
            if (c=='a'||c=='e'||c=='i'||c=='o'||c=='u') vowels++;
        }
    }
    return (alpha > 0) ? (float)vowels / alpha : 0.5f;
}

/*
 * ends_with_abused_tld(): 도메인명이 남용 TLD 중 하나로 끝나는지 확인.
 */
static bool ends_with_abused_tld(const char *name)
{
    size_t nlen = strlen(name);
    for (const auto &tld : ABUSED_TLDS) {
        size_t tlen = tld.size();
        if (nlen >= tlen && strcmp(name + nlen - tlen, tld.c_str()) == 0)
            return true;
    }
    return false;
}

/*
 * first_label_len(): 도메인의 첫 번째 레이블(서브도메인) 길이.
 */
static size_t first_label_len(const char *name)
{
    const char *dot = strchr(name, '.');
    return dot ? (size_t)(dot - name) : strlen(name);
}

std::vector<RuleMatch> match_rules(const dns_event &e)
{
    std::vector<RuleMatch> hits;

    if (comm_in(e.comm, DNS_WHITELIST)) return hits;

    const char *name = e.name;
    if (!name[0]) return hits;

    /*
     * R-018a: DNS 터널링 (레이블 길이 > 50자).
     * iodine, dnscat2 등이 Base32/Base64 인코딩 데이터를 서브도메인에 삽입.
     */
    if (max_label_len(name) > 50)
        hits.push_back({"R-018a", "DNS 터널링 의심 (레이블 > 50자)", "critical"});

    /*
     * R-018b: DGA 도메인 의심 (랜덤 서브도메인).
     * 첫 번째 레이블이 15자 초과 AND 모음 비율 < 0.15.
     */
    size_t fl = first_label_len(name);
    if (fl > 15 && vowel_ratio(name) < 0.15f)
        hits.push_back({"R-018b", "DGA 도메인 의심 (랜덤 서브도메인)", "high"});

    /*
     * R-018c: 남용 TLD 접속.
     * .tk/.ml/.ga/.cf/.gq (Freenom 무료 TLD) 등은 피싱/C2 서버에 많이 쓰인다.
     */
    if (ends_with_abused_tld(name))
        hits.push_back({"R-018c", "남용 TLD 접속 (.tk/.ml/.ga 등)", "medium"});

    return hits;
}

/* ── 네임스페이스 룰 ─────────────────────────────────────────────────────── */

/* CLONE_NEW* 플래그 상수 (userspace 헤더에서 공급) */
#include <sched.h>

std::vector<RuleMatch> match_rules(const ns_event &e)
{
    std::vector<RuleMatch> hits;

    if (comm_in(e.comm, NS_ESCAPE_WHITELIST)) return hits;

    /*
     * R-024: 컨테이너 탈출 시도.
     *
     * 공격 시나리오:
     *   컨테이너 내부에서 unshare(CLONE_NEWUSER | CLONE_NEWNS) 를 호출해
     *   새 사용자 네임스페이스에서 root 권한을 획득한 뒤,
     *   호스트 파일시스템 마운트 → 호스트 탈출 (CVE-2019-5736 류).
     *
     * in_container=1 + CLONE_NEWUSER: 컨테이너 내에서 새 user ns → 확실한 탈출 시도
     * in_container=1 + 복수 NS 플래그: 네임스페이스 전반 분리 → 탈출 준비
     * in_container=0 + CLONE_NEWUSER: 호스트에서의 권한 상승 시도 (덜 위험하지만 의심)
     */
    bool has_newuser = (e.flags & CLONE_NEWUSER) != 0;
    bool has_newpid  = (e.flags & CLONE_NEWPID)  != 0;
    bool has_newns   = (e.flags & CLONE_NEWNS)   != 0;

    /* 설정된 NS 플래그 수 계산 */
    int ns_count = 0;
    if (e.flags & CLONE_NEWUSER)   ns_count++;
    if (e.flags & CLONE_NEWPID)    ns_count++;
    if (e.flags & CLONE_NEWNS)     ns_count++;
    if (e.flags & CLONE_NEWNET)    ns_count++;
    if (e.flags & CLONE_NEWIPC)    ns_count++;
    if (e.flags & CLONE_NEWUTS)    ns_count++;
    if (e.flags & CLONE_NEWCGROUP) ns_count++;

    if (e.in_container && has_newuser)
        hits.push_back({"R-024",
                        "컨테이너 탈출 시도: 컨테이너 내 사용자 네임스페이스 분리",
                        "critical"});
    else if (e.in_container && ns_count >= 2)
        hits.push_back({"R-024",
                        "컨테이너 탈출 의심: 복수 네임스페이스 동시 분리",
                        "high"});
    else if (has_newuser && (has_newpid || has_newns))
        hits.push_back({"R-024",
                        "사용자 네임스페이스 + mount/pid 분리 (권한 상승 의심)",
                        "medium"});

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
