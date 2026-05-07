/*
 * rule_config.cpp - YAML 서브셋 파서 + 기본값 초기화
 *
 * 지원 YAML 문법:
 *   # 주석 줄           → 무시
 *   section_name:       → 현재 섹션 전환 (콜론으로 끝나는 줄)
 *     - value           → 현재 섹션에 항목 추가 (선행 공백 무시)
 *   (빈 줄)             → 무시
 *
 * 파싱 오류(알 수 없는 섹션, 잘못된 포트 번호 등)는 조용히 무시한다.
 * 전체 파일이 깨져도 파싱된 항목은 유지되므로 안전하다.
 */
#include "rules/rule_config.h"
#include <cstdlib>    /* strtoul */
#include <fstream>
#include <unordered_map>

/* 선행/후행 공백(스페이스, 탭, CR, LF) 제거 */
static std::string trim(const std::string &s)
{
    const char *ws = " \t\r\n";
    size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

bool RuleConfig::load(const std::string &path)
{
    std::ifstream f(path);
    if (!f.is_open()) return false;

    /*
     * 파일을 열었으면 모든 목록을 초기화하고 YAML 내용으로 완전히 교체한다.
     * 섹션이 YAML 에 없으면 해당 목록은 빈 채로 유지된다.
     */
    sensitive_paths.clear();  log_paths.clear();       tmp_exec_paths.clear();
    shell_tools.clear();      interpreters.clear();    shells.clear();
    web_servers.clear();      db_servers.clear();      pkg_manager_comms.clear();
    bind_whitelist.clear();   sys_write_whitelist.clear();
    outbound_whitelist.clear(); setuid_whitelist.clear();
    ptrace_whitelist.clear(); memfd_whitelist.clear();
    dns_whitelist.clear();    ns_escape_whitelist.clear();
    abused_tlds.clear();      common_ports.clear();

    /*
     * 섹션 이름 → 문자열 벡터 포인터 맵.
     * 알려진 섹션만 처리하고 나머지는 cur_str=nullptr 로 넘어간다.
     */
    std::unordered_map<std::string, std::vector<std::string>*> str_map = {
        {"sensitive_paths",     &sensitive_paths},
        {"log_paths",           &log_paths},
        {"tmp_exec_paths",      &tmp_exec_paths},
        {"shell_tools",         &shell_tools},
        {"interpreters",        &interpreters},
        {"shells",              &shells},
        {"web_servers",         &web_servers},
        {"db_servers",          &db_servers},
        {"pkg_manager_comms",   &pkg_manager_comms},
        {"bind_whitelist",      &bind_whitelist},
        {"sys_write_whitelist", &sys_write_whitelist},
        {"outbound_whitelist",  &outbound_whitelist},
        {"setuid_whitelist",    &setuid_whitelist},
        {"ptrace_whitelist",    &ptrace_whitelist},
        {"memfd_whitelist",     &memfd_whitelist},
        {"dns_whitelist",       &dns_whitelist},
        {"ns_escape_whitelist", &ns_escape_whitelist},
        {"abused_tlds",         &abused_tlds},
    };

    std::vector<std::string> *cur_str  = nullptr;
    bool                      cur_port = false;

    std::string line;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        /* 목록 항목: "- value" (선행 공백은 trim() 에서 제거됨) */
        if (t.size() >= 2 && t[0] == '-' && t[1] == ' ') {
            std::string val = trim(t.substr(2));
            if (val.empty()) continue;

            if (cur_port) {
                /* 포트 섹션: 숫자만 허용 */
                char *end;
                unsigned long p = std::strtoul(val.c_str(), &end, 10);
                if (end != val.c_str() && p > 0 && p <= 65535)
                    common_ports.push_back(static_cast<uint16_t>(p));
            } else if (cur_str) {
                cur_str->push_back(val);
            }
            continue;
        }

        /* 섹션 헤더: "key:" (콜론으로 끝나는 줄) */
        if (!t.empty() && t.back() == ':') {
            std::string key = t.substr(0, t.size() - 1);
            cur_port = (key == "common_ports");
            auto it = str_map.find(key);
            cur_str = (it != str_map.end()) ? it->second : nullptr;
        }
    }

    return true;
}

void RuleConfig::load_defaults()
{
    sensitive_paths  = {"/etc/", "/boot/", "/bin/", "/sbin/",
                        "/usr/bin/", "/usr/sbin/",
                        "/lib/", "/lib64/", "/usr/lib/"};

    log_paths        = {"/var/log/", "/run/log/"};

    tmp_exec_paths   = {"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"};

    shell_tools      = {"nc", "ncat", "netcat", "socat",
                        "nmap", "masscan",
                        "msfconsole", "msfvenom",
                        "empire", "covenant"};

    interpreters     = {"python", "python2", "python3",
                        "perl", "ruby", "php", "lua",
                        "node", "nodejs"};

    shells           = {"bash", "sh", "dash", "zsh", "ksh", "fish", "tcsh", "csh"};

    web_servers      = {"nginx", "apache", "apache2", "httpd", "lighttpd",
                        "caddy", "traefik", "gunicorn", "uwsgi", "php-fpm"};

    db_servers       = {"mysqld", "mysqld_safe", "mariadbd",
                        "postgres", "postmaster",
                        "mongod", "redis-server", "memcached"};

    pkg_manager_comms = {"apt", "apt-get", "dpkg", "dpkg-preconfig",
                          "pip", "pip3",
                          "npm", "yarn", "pnpm",
                          "cargo", "rustc",
                          "make", "cmake", "ninja",
                          "gradle", "mvn"};

    bind_whitelist   = {"systemd", "systemd-resolve", "dbus-daemon",
                        "NetworkManage",
                        "avahi-daemon", "cupsd", "cups-browsed",
                        "rsyslogd", "journald", "snapd",
                        "sshd",
                        "dockerd", "containerd", "containerd-shi",
                        "libvirtd", "virtlogd",
                        "nginx", "apache", "apache2", "httpd", "lighttpd",
                        "gunicorn", "uwsgi", "php-fpm",
                        "mysqld", "mysqld_safe", "mariadbd",
                        "postgres", "postmaster",
                        "mongod", "redis-server", "memcached"};

    sys_write_whitelist = {"dpkg", "dpkg-unpack", "dpkg-preconfig",
                           "apt", "apt-get",
                           "update-alterna",
                           "rpm", "yum", "dnf", "zypper",
                           "snap", "snapd"};

    outbound_whitelist  = {"apt", "apt-get", "apt-transport",
                           "curl", "wget",
                           "git", "git-remote-http",
                           "snap", "snapd"};

    setuid_whitelist    = {"sudo", "su", "newgrp", "passwd", "chsh", "chfn",
                           "chage", "gpasswd",
                           "ping", "ping6", "traceroute6",
                           "pkexec",
                           "crontab", "at",
                           "mount", "umount", "fusermount", "fusermount3",
                           "ssh", "ssh-agent"};

    ptrace_whitelist    = {"gdb", "lldb", "strace", "ltrace",
                           "perf", "valgrind", "rr"};

    memfd_whitelist     = {"java", "node", "nodejs",
                           "qemu-system-x86", "qemu-system-arm", "qemu-kvm",
                           "systemd",
                           "firefox", "chromium", "chromium-browse",
                           "Xwayland"};

    dns_whitelist       = {"systemd-resolve", "avahi-daemon"};

    /*
     * ns_escape_whitelist: 합법적으로 네임스페이스를 분리하는 도구.
     *
     * newuidmap/newgidmap: 컨테이너 런타임이 사용자 네임스페이스 UID 매핑 설정
     * unshare: 동명의 userspace 유틸리티 (unshare --user 등 정상 사용)
     * systemd-nspawn: systemd 컨테이너 (테스트/개발용)
     * bwrap: Bubblewrap 샌드박스 (Flatpak, 브라우저 sandbox)
     * lxc-start/lxc-unshare: LXC 컨테이너 관리자
     * podman/docker: 컨테이너 런타임
     */
    ns_escape_whitelist = {"newuidmap", "newgidmap",
                           "unshare",
                           "systemd-nspawn",
                           "bwrap",
                           "lxc-start", "lxc-unshare",
                           "podman", "docker"};

    abused_tlds         = {".tk", ".ml", ".ga", ".cf", ".gq",
                           ".xyz", ".top", ".work", ".click"};

    common_ports        = {
        /* 표준 프로토콜 */
        21, 22, 25, 53, 80, 110, 143,
        443, 465, 587, 993, 995,
        /* 데이터베이스 */
        1433, 3306, 5432, 6379, 27017,
        /* 웹/API */
        8080, 8443, 8888, 9200,
        /* 개발 서버 */
        3000, 4200, 5000, 5173, 8000,
        /* 모니터링·오케스트레이션 */
        9090, 9100, 6443, 10250, 2375, 2376
    };
}
