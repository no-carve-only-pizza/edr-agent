#include "anomaly/behavior_profiler.h"
#include <cmath>

/* ── 카운터 증가 ────────────────────────────────────────────────────────── */

void BehaviorProfiler::inc_net_connect(const char *comm)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_profiles[comm].net_connect.cur_count++;
}

void BehaviorProfiler::inc_file_write(const char *comm)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_profiles[comm].file_write.cur_count++;
}

void BehaviorProfiler::inc_exec(const char *comm)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_profiles[comm].exec.cur_count++;
}

/* ── EWMA 갱신 + Z-점수 계산 ───────────────────────────────────────────── */

AnomalyHit BehaviorProfiler::update_metric(const std::string &comm,
                                            MetricState &m,
                                            const std::string &name,
                                            uint64_t count)
{
    double x = static_cast<double>(count);

    AnomalyHit hit{};
    hit.comm     = comm;
    hit.metric   = name;
    hit.observed = x;

    double old_mean = m.ewma_mean;

    if (m.windows == 0) {
        m.ewma_mean = x;
        m.ewma_var  = 0.0;
    } else {
        m.ewma_mean = ALPHA * x + (1.0 - ALPHA) * old_mean;
        m.ewma_var  = (1.0 - ALPHA) * (m.ewma_var + ALPHA * (x - old_mean) * (x - old_mean));
    }
    m.windows++;
    m.cur_count = 0;

    if (m.windows > MIN_WINDOWS) {
        double stddev = std::sqrt(m.ewma_var + 1e-6);
        hit.mean   = old_mean;
        hit.stddev = stddev;
        hit.zscore = std::abs(x - old_mean) / stddev;
    }
    /* windows <= MIN_WINDOWS: hit.zscore = 0.0 (학습 단계, 이상 판정 없음) */

    return hit;
}

/* ── tick(): 만료 윈도우 처리 + 이상 탐지 ──────────────────────────────── */

std::vector<AnomalyHit> BehaviorProfiler::tick(uint64_t now_sec)
{
    std::vector<AnomalyHit> results;

    std::lock_guard<std::mutex> lk(m_mtx);

    for (auto &[comm, cs] : m_profiles) {
        if (cs.window_start == 0) {
            cs.window_start = now_sec;
            continue;
        }
        if (now_sec - cs.window_start < static_cast<uint64_t>(WINDOW_SECS))
            continue;

        cs.window_start = now_sec;

        auto hit_net  = update_metric(comm, cs.net_connect, "net_connect", cs.net_connect.cur_count);
        auto hit_fw   = update_metric(comm, cs.file_write,  "file_write",  cs.file_write.cur_count);
        auto hit_exec = update_metric(comm, cs.exec,        "exec",        cs.exec.cur_count);

        if (hit_net.zscore  >= Z_THRESHOLD) results.push_back(hit_net);
        if (hit_fw.zscore   >= Z_THRESHOLD) results.push_back(hit_fw);
        if (hit_exec.zscore >= Z_THRESHOLD) results.push_back(hit_exec);
    }

    return results;
}
