#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <vector>

/*
 * BehaviorProfiler: EWMA(지수 가중 이동 평균) + Z-점수 기반 행동 이상 탐지 (R-028).
 *
 * 프로세스 comm 별로 60초 윈도우 내 이벤트 빈도를 추적하여
 * 과거 패턴에서 크게 벗어나면 이상 징후로 판정한다.
 *
 * 측정 지표:
 *   - net_connect : 아웃바운드 connect() 횟수
 *   - file_write  : 파일 쓰기(openat W) 횟수
 *   - exec        : execve 횟수
 *
 * 알고리즘:
 *   EWMA 갱신:  μ_new = α × x + (1-α) × μ_old   (α = 0.2)
 *   분산 갱신:  σ²    = (1-α) × (σ² + α × (x-μ_old)²)
 *   Z-점수:     z     = |x - μ| / (√σ² + ε)
 *   이상 판정:  z ≥ Z_THRESHOLD (기본 3.0) AND 과거 윈도우 ≥ MIN_WINDOWS (기본 3)
 */

struct AnomalyHit {
    std::string comm;
    std::string metric;   /* "net_connect" | "file_write" | "exec" */
    double      observed; /* 이번 윈도우 관측값 */
    double      mean;     /* EWMA 평균 */
    double      stddev;   /* EWMA 표준편차 */
    double      zscore;
};

class BehaviorProfiler {
public:
    static constexpr double ALPHA        = 0.2;
    static constexpr double Z_THRESHOLD  = 3.0;
    static constexpr int    MIN_WINDOWS  = 3;   /* 최소 학습 윈도우 수 */
    static constexpr int    WINDOW_SECS  = 60;

    BehaviorProfiler() = default;

    /* 이벤트 카운터 증가 (이벤트 핸들러에서 호출) */
    void inc_net_connect(const char *comm);
    void inc_file_write (const char *comm);
    void inc_exec       (const char *comm);

    /* 현재 시각(UNIX 초)을 받아 만료된 윈도우를 EWMA에 반영하고
     * 이상 탐지 결과를 반환한다. main 루프에서 주기적으로 호출. */
    std::vector<AnomalyHit> tick(uint64_t now_sec);

private:
    struct MetricState {
        double   ewma_mean = 0.0;
        double   ewma_var  = 0.0;
        int      windows   = 0;   /* 학습한 윈도우 수 */
        uint64_t cur_count = 0;   /* 현재 윈도우 내 카운트 */
    };

    struct CommState {
        MetricState net_connect;
        MetricState file_write;
        MetricState exec;
        uint64_t window_start = 0; /* 현재 윈도우 시작 시각(초) */
    };

    AnomalyHit update_metric(const std::string &comm,
                              MetricState &m,
                              const std::string &name,
                              uint64_t count);

    std::unordered_map<std::string, CommState> m_profiles;
    mutable std::mutex m_mtx;
};
