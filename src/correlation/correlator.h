#pragma once
/*
 * correlator.h - 이벤트 상관 분석 엔진
 *
 * ┌─ 설계 원리 ─────────────────────────────────────────────────────────────┐
 * │                                                                          │
 * │  단일 이벤트 룰(R-001~R-018)은 개별 syscall 을 독립적으로 평가한다.    │
 * │  실제 공격은 여러 단계로 이루어지므로, 동일 PID 의 이벤트 시퀀스를     │
 * │  시간 창 내에서 분석해야 고신뢰도 알림이 가능하다.                     │
 * │                                                                          │
 * │  예: ptrace(ATTACH) 만으로는 디버거 가능성 있음 (낮은 신뢰도)          │
 * │      ptrace + memfd_create 조합 → 프로세스 인젝션 거의 확실 (높은 신뢰도)│
 * │                                                                          │
 * │  구현 방식: 슬라이딩 윈도우 히스토리                                    │
 * │    - PID 별로 최근 이벤트를 deque 에 보관                              │
 * │    - 새 이벤트 도착 시 기존 히스토리에서 패턴 완성 여부 확인           │
 * │    - 패턴 완성 → 상관 룰 RuleMatch 반환                                │
 * │    - MAX_WINDOW_NS(60초) 초과 항목은 자동 만료                         │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * 상관 룰 목록:
 *   R-019: ptrace    ↔ memfd_create     (30s)  → 프로세스 인젝션 체인
 *   R-020: exec_tmp  ↔ net_connect      (60s)  → 드로퍼 + C2 콜백
 *   R-021: write_tmp + exec_tmp         (60s)  → 다운로드 후 실행
 *   R-022: mem_rwx   ↔ net_connect      (30s)  → 파일리스 C2 비콘
 *   R-023: dns_susp  ↔ net_connect      (30s)  → C2 도메인 조회 후 연결
 */
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <vector>
#include "rules/rule_engine.h"

/*
 * CorrelEvt: 상관 분석에 사용하는 추상화된 이벤트 종류.
 *
 * 원본 이벤트 구조체(process_event 등)의 세부 필드를 여기서 모두 저장하지 않고,
 * "어떤 종류의 행위였는가"만 기록한다. 세부 내용은 단일 이벤트 룰이 이미 판단함.
 */
enum class CorrelEvt : uint8_t {
    EXEC_TMP  = 1, /* /tmp, /dev/shm 등 임시 경로에서 exec               */
    WRITE_TMP = 2, /* /tmp 등에 파일 쓰기                                 */
    NET_CONN  = 3, /* 아웃바운드 connect()                                */
    PTRACE    = 4, /* ptrace ATTACH / SEIZE                               */
    MEM_RWX   = 5, /* mmap/mprotect PROT_WRITE|PROT_EXEC                 */
    MEMFD     = 6, /* memfd_create()                                      */
    DNS_SUSP  = 7, /* R-018 이 발화한 의심 DNS 쿼리                       */
};

class CorrelationEngine {
public:
    /*
     * feed(): 새 이벤트를 기록하고 완성된 상관 패턴을 반환한다.
     *
     * 호출 순서:
     *   1. 기존 히스토리에서 패턴 완성 여부 확인 (패턴 체크)
     *   2. 새 이벤트를 히스토리에 추가 (자기 자신과 매칭 방지)
     *
     * 반환값: 이번 이벤트로 완성된 상관 룰 목록 (비어 있으면 패턴 미완성).
     */
    std::vector<RuleMatch> feed(uint32_t pid, CorrelEvt kind, uint64_t ts_ns);

    /* remove(): 프로세스 종료 시 PID 히스토리 제거 (메모리 해제). */
    void remove(uint32_t pid);

private:
    struct Record {
        CorrelEvt kind;
        uint64_t  ts_ns;
    };

    /* 60초: 가장 긴 상관 윈도우. 이 이상 오래된 이벤트는 만료. */
    static constexpr uint64_t MAX_WINDOW_NS = 60ULL * 1'000'000'000ULL;
    static constexpr uint64_t W30           = 30ULL * 1'000'000'000ULL;
    static constexpr uint64_t W60           = MAX_WINDOW_NS;

    /* PID 당 최대 기록 이벤트 수 (오래된 것 자동 삭제). */
    static constexpr size_t MAX_RECORDS = 32;

    std::unordered_map<uint32_t, std::deque<Record>> hist_;

    /* 만료된(MAX_WINDOW_NS 초과) 항목 제거. */
    void evict(uint32_t pid, uint64_t now_ns);

    /*
     * seen(): 히스토리에서 지정 종류의 이벤트가 within_ns 이내에 있는지 확인.
     * 패턴 체크 후 새 이벤트를 추가하므로 자기 자신은 포함되지 않는다.
     */
    bool seen(uint32_t pid, CorrelEvt kind,
              uint64_t now_ns, uint64_t within_ns) const;
};
