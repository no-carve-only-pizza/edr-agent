#pragma once
/*
 * proc_tree.h - 유저스페이스 프로세스 트리 캐시
 *
 * ┌─ 목적 ──────────────────────────────────────────────────────────────────┐
 * │  BPF 이벤트에는 pid/ppid 만 담겨 있어 "부모 프로세스의 comm" 을        │
 * │  직접 알 수 없다. ProcTree 는 exec 이벤트를 누적해 트리를 유지하고,   │
 * │  임의 PID 의 comm 을 O(1) 로 조회할 수 있게 한다.                     │
 * │                                                                         │
 * │  활용 예:                                                               │
 * │    nginx(pid=100) → bash(pid=200)  : 웹셸 탐지 R-011                  │
 * │    mysqld(pid=50) → python(pid=300): SQLi RCE 탐지 R-012              │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * 생명주기:
 *   init_from_proc() : 에이전트 시작 시 /proc/<pid>/status 를 순회하여
 *                      이미 실행 중인 프로세스로 초기 트리를 구성한다.
 *   update()         : sched_process_exec 이벤트 수신 시 호출 (트리 갱신).
 *   comm_of(pid)     : 부모 PID 의 comm 조회 (규칙 매칭에 사용).
 *
 * 정리(cleanup):
 *   프로세스 종료 이벤트(sched_process_exit)를 BPF 로 수신하면 remove() 로
 *   정리할 수 있다. 현 PoC 에서는 생략하고 자연 교체(overwrite)에 의존한다.
 *   (동일 PID 재사용 시 update() 가 덮어쓴다)
 */

#include <cstdint>
#include <string>
#include <unordered_map>
#include "common.h"

struct ProcNode {
    uint32_t ppid;
    char     comm[TASK_COMM_LEN]; /* task_struct.comm (15글자 + NUL) */
};

class ProcTree {
    std::unordered_map<uint32_t, ProcNode> nodes_;

public:
    /*
     * init_from_proc: /proc/<pid>/status 를 파싱해 현재 실행 중인 프로세스로
     * 트리를 초기화한다. 에이전트 시작 이전부터 실행 중인 서비스(nginx 등)의
     * comm 을 알기 위해 필수적이다.
     */
    void init_from_proc();

    /* exec 이벤트마다 호출: 트리에 pid 항목을 추가 또는 갱신 */
    void update(uint32_t pid, uint32_t ppid, const char *comm);

    /* pid 의 comm 반환. 트리에 없으면 nullptr */
    const char *comm_of(uint32_t pid) const;

    /* 프로세스 종료 시 항목 제거 (선택적) */
    void remove(uint32_t pid) { nodes_.erase(pid); }

    size_t size() const { return nodes_.size(); }
};
