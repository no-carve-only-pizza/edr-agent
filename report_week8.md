# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-08  
**작성자:** (본인 이름)

---

## 1. 개요

8주차에는 **EWMA(Exponentially Weighted Moving Average) 기반 행동 이상 탐지(R-028)**를 구현하였다. 위협 인텔 피드가 "이미 알려진" 공격을 탐지한다면, R-028은 **정상 패턴에서의 이탈**을 탐지해 알려지지 않은(zero-day) 공격을 포착한다.

---

## 2. 단일 이벤트 탐지의 한계와 이상 탐지의 필요성

지금까지 구현한 R-001 ~ R-027은 개별 이벤트(또는 이벤트 조합)의 **패턴**을 판단한다. 그러나:

| 한계 | 예시 |
|---|---|
| 새로운 공격 도구는 탐지 불가 | 서명에 없는 신종 C2 도구 |
| 화이트리스트 우회 가능 | 신뢰된 바이너리(`curl`, `python`)를 악용하는 LotL 공격 |
| 정상 프로세스의 비정상 행동 | 웹 서버가 갑자기 대량 파일을 쓰기 시작 |

행동 기반 이상 탐지는 "특정 행동 자체"가 아닌 **"해당 프로세스의 과거 패턴과의 차이"**를 측정한다.

---

## 3. 구현: EWMA + Z-점수 행동 이상 탐지

### 3.1 측정 지표

| 지표 | 카운터 증가 시점 | 탐지 대상 |
|---|---|---|
| `net_connect` | `EVENT_NET_CONNECT` | C2 비콘, 데이터 유출 |
| `file_write` | `EVENT_FILE_WRITE` | 랜섬웨어, 백도어 설치 |
| `exec` | `EVENT_PROC_EXEC` | 권한 상승, 탈출 도구 실행 |

### 3.2 알고리즘

60초 윈도우 단위로 각 지표의 이벤트 카운트를 측정하고, EWMA로 장기 평균을 학습한다.

```
EWMA 갱신:  μ_new = α × x + (1 - α) × μ_old          (α = 0.2)
분산 갱신:  σ²    = (1 - α) × (σ² + α × (x - μ_old)²)
Z-점수:     z     = |x - μ_old| / (√σ² + ε)
이상 판정:  z ≥ 3.0  AND  학습 윈도우 수 ≥ 3
```

- **α = 0.2**: 최근 관측값에 20% 가중, 과거 패턴에 80% 가중. 너무 작으면 변화에 둔감, 너무 크면 노이즈에 민감.
- **MIN_WINDOWS = 3**: 학습 데이터가 충분하지 않은 초기 단계에서 오탐(FP) 방지.
- **Z_THRESHOLD = 3.0**: 정규 분포에서 0.3% 확률에 해당하는 이벤트만 탐지 (FP 억제).

### 3.3 구현 구조

```cpp
class BehaviorProfiler {
    struct MetricState {
        double   ewma_mean = 0.0;
        double   ewma_var  = 0.0;
        int      windows   = 0;
        uint64_t cur_count = 0;
    };

    struct CommState {
        MetricState net_connect;
        MetricState file_write;
        MetricState exec;
        uint64_t    window_start = 0;
    };

    std::unordered_map<std::string, CommState> m_profiles;
    std::mutex m_mtx;
};
```

`inc_*(comm)` 은 이벤트 핸들러에서 직접 호출하고, `tick(now_sec)` 은 메인 루프에서 30초마다 호출하여 윈도우가 만료된 프로세스의 이상 점수를 계산한다.

```
이벤트 핸들러                    메인 폴 루프 (30초마다)
─────────────────────            ────────────────────────────
inc_net_connect("curl") ──▶      tick(now_sec)
inc_file_write("nginx")           │  윈도우 만료 검사
inc_exec("bash")         ──▶      │  EWMA 갱신
                                  │  Z-점수 계산
                                  └─▶ emit_anomaly() (z ≥ 3.0)
```

### 3.4 이상 탐지 알림 출력

```
[ANOML]  7200.000s  comm=nginx            metric=file_write    obs=1200  mean=12.3  z=8.4
  [ALERT] R-028 | 행동 이상 탐지 (EWMA Z=8.4, 임계값=3.0)
```

5분 중복 억제(anomaly dedup) 적용: 같은 `(comm, metric)` 조합은 5분 이내 재발화 억제.

NDJSON:
```json
{"type":"anomaly","ts":7200.000,"comm":"nginx","metric":"file_write",
 "observed":1200.00,"mean":12.30,"stddev":3.20,"zscore":8.41,
 "alerts":[{"id":"R-028","name":"행동 이상 탐지 (EWMA 기반)","sev":"high"}]}
```

---

## 4. 구체적 탐지 시나리오

### 4.1 랜섬웨어 (file_write 급증)

```
평소 nginx file_write: 5~10 회/분
랜섬웨어 감염 후:      5,000 회/분 → Z = 50+ → R-028 critical
```

### 4.2 LotL C2 비콘 (net_connect 증가)

```
평소 python net_connect: 0~2 회/분 (라이브러리 업데이트)
임플란트 감염 후:         30 회/분 (주기적 C2 체크인)
→ R-028 발화 (위협 인텔 DB에 없는 새 C2 서버도 탐지)
```

### 4.3 권한 상승 툴체인 (exec 급증)

```
평소 bash exec: 2~5 회/분 (cron, 셸 스크립트)
공격자 진입 후: 50 회/분 (자동화 툴 실행) → R-028 발화
```

---

## 5. 전체 탐지 룰 목록 (R-001 ~ R-028)

| ID | 이름 | 심각도 | 방식 |
|---|---|---|---|
| R-001 ~ R-024 | (6주차 보고서 참조) | high~critical | 단일/상관 이벤트 |
| R-025 | 알려진 C2 서버 IP 연결 | critical | 위협 인텔 (Feodo Tracker) |
| R-026 | 악성 도메인 DNS 조회 | critical | 위협 인텔 (URLhaus) |
| R-027 | 알려진 악성 파일 해시 실행 | critical | 해시 DB (MalwareBazaar) |
| R-028 | 행동 이상 탐지 (EWMA) | high | ML 이상 탐지 |

---

## 6. 프로젝트 현황 요약

| 분류 | 기술 | 구현 여부 |
|---|---|---|
| 커널 계측 | eBPF 트레이스포인트 (6개 BPF 프로그램) | ✅ |
| 탐지 엔진 | 단일 이벤트 룰 (R-001 ~ R-018, R-024 ~ R-027) | ✅ |
| 상관 분석 | 슬라이딩 윈도우 상관 (R-019 ~ R-023) | ✅ |
| 위협 인텔 | Feodo Tracker IP + URLhaus 도메인 + 해시 DB | ✅ |
| ML 이상 탐지 | EWMA + Z-점수 (R-028) | ✅ |
| 출력 | 터미널 컬러 테이블 + NDJSON + HTTP POST | ✅ |
| 설정 외부화 | YAML 룰 파일 (`--rules`) | ✅ |

## 7. 남은 과제

- **백엔드 연동 검증**: `--endpoint` HTTP POST 실 환경 테스트
- **성능 측정**: 고부하 환경에서 ring_buffer dropped events 측정
- **EWMA 임계값 튜닝**: 운영 환경별 FP/FN 균형 조정
- **MalwareBazaar API 자동 갱신**: 현재 파일 로드 방식 → HTTP API 갱신으로 확장 가능
