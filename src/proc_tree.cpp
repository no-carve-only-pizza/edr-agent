/*
 * proc_tree.cpp - 프로세스 트리 캐시 구현
 *
 * /proc/<pid>/status 파일 형식 (관련 필드만):
 *
 *   Name:   nginx          ← task_struct.comm (15글자 한도)
 *   ...
 *   Pid:    1234           ← 유저스페이스 PID (커널 TGID)
 *   PPid:   1              ← 부모 PID
 *   ...
 *
 * 파싱 전략: fgets() 로 한 줄씩 읽으며 "Name:" / "PPid:" 두 필드를 찾으면
 * 즉시 파일을 닫는다 (전체 파일 읽기 불필요).
 */

#include "proc_tree.h"
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>

void ProcTree::update(uint32_t pid, uint32_t ppid, const char *comm)
{
    ProcNode &n  = nodes_[pid];
    n.ppid       = ppid;
    strncpy(n.comm, comm, TASK_COMM_LEN - 1);
    n.comm[TASK_COMM_LEN - 1] = '\0';
}

const char *ProcTree::comm_of(uint32_t pid) const
{
    auto it = nodes_.find(pid);
    return (it != nodes_.end()) ? it->second.comm : nullptr;
}

void ProcTree::init_from_proc()
{
    DIR *d = opendir("/proc");
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        /*
         * /proc/ 하위 항목 중 숫자로만 이루어진 디렉터리 = PID 디렉터리.
         * 커널 스레드(kthread)도 포함되지만 comm 이 기록되어 있어 무방하다.
         */
        const char *dname = ent->d_name;
        bool is_pid = (dname[0] != '\0');
        for (const char *p = dname; *p; ++p)
            if (!isdigit((unsigned char)*p)) { is_pid = false; break; }
        if (!is_pid) continue;

        uint32_t pid = (uint32_t)atoi(dname);
        if (pid == 0) continue;

        /* %u 최대 10자리 + "/proc/" + "/status" + NUL = 24바이트 → 64로 충분 */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%u/status", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue; /* 프로세스가 방금 종료됐을 수 있음 */

        ProcNode node  = {};
        char     line[256];
        int      found = 0; /* Name + PPid 두 필드 모두 찾으면 조기 종료 */

        while (found < 2 && fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:\t", 6) == 0) {
                /* sscanf %15s: 공백 포함 이름은 잘리지만 comm 은 공백 없음 */
                sscanf(line + 6, "%15s", node.comm);
                found++;
            } else if (strncmp(line, "PPid:\t", 6) == 0) {
                sscanf(line + 6, "%u", &node.ppid);
                found++;
            }
        }
        fclose(f);

        if (node.comm[0] != '\0')
            nodes_[pid] = node;
    }
    closedir(d);
}
