# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-08  
**작성자:** (본인 이름)

---

## 1. 개요

7주차에는 **위협 인텔리전스(Threat Intelligence) 피드 연동**과 **파일 해시 탐지**를 구현하였다.

1. **C2 IP 피드 연동 (R-025)**: Feodo Tracker IP 블록리스트 → 알려진 C2 서버 연결 탐지
2. **악성 도메인 DNS 탐지 (R-026)**: URLhaus 도메인 피드 → 악성 도메인 DNS 조회 탐지
3. **파일 해시 탐지 (R-027)**: SHA-256 해시 DB → 실행 파일 악성 해시 대조
4. **SHA-256 헤더 전용 구현**: 외부 라이브러리 없이 FIPS 180-4 기반 순수 C++ 구현

---

## 2. 구현 내용

### 2.1 위협 인텔리전스 피드 아키텍처

#### 2.1.1 설계 결정: 인라인 vs. 백그라운드 갱신

| | 인라인 갱신 | 백그라운드 스레드 |
|---|---|---|
| 이벤트 처리 지연 | 피드 다운로드 시간(수초)만큼 블록 | 없음 |
| 구현 복잡도 | 낮음 | 중간 (`std::thread` + `std::shared_mutex`) |
| 에이전트 가용성 | 갱신 중 탐지 불가 | 탐지 계속 동작 |

탐지 연속성이 핵심이므로 **백그라운드 스레드** 방식을 채택하였다.

#### 2.1.2 스레드 안전성 설계

```cpp
class FeedManager {
    mutable std::shared_mutex           m_mtx;
    std::unordered_set<uint32_t>        m_c2_ips;     /* 네트워크 바이트 오더 IPv4 */
    std::unordered_set<std::string>     m_mal_domains;

    /* 이벤트 핸들러(빈번) → shared_lock: 다중 동시 읽기 허용 */
    bool is_c2_ip4(uint32_t ip_net) const;

    /* 백그라운드 갱신 → unique_lock: 원자적 교체 */
    void fetch_once();
};
```

- **읽기**: `shared_lock` → 이벤트 핸들러가 동시에 여러 스레드에서 조회 가능
- **쓰기**: `unique_lock` → 피드 교체 중 읽기 차단
- **`std::condition_variable`**: 갱신 주기(기본 6시간) 대기 + `stop()` 시 즉시 깨어남

```
메인 스레드                    백그라운드 스레드
─────────────────              ──────────────────────────────
FeedManager::start()  ──────▶  fetch_once()  ← 최초 로드
                               │
이벤트 발생                     cv.wait_for(6h)
→ is_c2_ip4(ip)                │
  ↑ shared_lock                fetch_once()  ← 주기 갱신
  (블록 없음)                   │ unique_lock (교체 중)
                               │ m_c2_ips = new_ips;
```

#### 2.1.3 도메인 피드 파싱 및 suffix 매칭

URLhaus 피드 포맷: `http://evil.com/malware.exe`

파싱 단계:
1. `://` 이후 추출 → 호스트 부분 격리
2. 첫 `/` 이전까지 → 경로 제거
3. 마지막 `:` 이전까지 → 포트 제거
4. 결과: `"evil.com"` 저장

조회 시 suffix 매칭:
```
query: "sub.evil.com"
  → "sub.evil.com"  (X)
  → "evil.com"      (O) ← 피드 항목과 일치
```

이를 통해 피드에 `"evil.com"` 하나만 등록해도 모든 서브도메인을 탐지한다.

### 2.2 C2 IP 탐지 (R-025)

```
Feodo Tracker IP 블록리스트 (Botnet C2 전용):
  185.220.101.45
  45.33.32.156
  ...
```

`handle_net_event()` 에서 `EVENT_NET_CONNECT` + `AF_INET` 이면:

```cpp
uint32_t ip4;
memcpy(&ip4, e.daddr, 4);  /* 네트워크 바이트 오더 그대로 */
if (g_feeds->is_c2_ip4(ip4))
    → R-025: 알려진 C2 서버 IP 연결 탐지 (critical)
```

### 2.3 악성 도메인 탐지 (R-026)

`handle_dns_event()` 에서 DNS 조회 도메인을 피드와 대조:

```cpp
if (g_feeds->is_malicious_domain(e.name))
    → R-026: 악성 도메인 DNS 조회 탐지 (critical)
```

### 2.4 파일 해시 탐지 (R-027)

#### 2.4.1 SHA-256 헤더 전용 구현

`OpenSSL`, `mbedTLS` 등 외부 라이브러리 없이 FIPS PUB 180-4 기반 SHA-256을 `src/threat_intel/sha256.h` 에 단일 헤더로 구현하였다.

```cpp
namespace sha256 {
    static void transform(uint32_t s[8], const uint8_t d[64]);

    inline std::string hash_file(const char *path) {
        // 4096바이트 단위로 읽기, 64바이트 블록 처리
        // 패딩: 0x80 || 0...0 || bit_count (64-bit big-endian)
        // 반환: 64자 소문자 16진수 문자열
    }
}
```

검증 기준:
```bash
# 빈 파일 해시
echo -n "" | sha256sum
→ e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# EICAR 테스트 파일
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    | sha256sum
→ 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

#### 2.4.2 HashChecker 클래스

```cpp
class HashChecker {
    std::unordered_set<std::string> m_hashes;
public:
    bool load(const std::string &path);  /* known_hashes.txt 로드 */
    bool check_file(const char *path);  /* sha256::hash_file() → DB 조회 */
    bool check_hash(const std::string &hex);
};
```

`handle_proc_event()` 에서 exec 이벤트 시 파일 해시 대조:

```cpp
if (g_hash && g_hash->check_file(e.filename))
    → R-027: 알려진 악성 파일 해시 탐지 (MalwareBazaar) (critical)
```

### 2.5 YAML 스칼라 값 파싱 확장

기존 YAML 파서는 목록 항목(`- value`)만 지원했다. 피드 URL과 같은 스칼라 값을 지원하기 위해 `key: value` 파싱을 추가하였다.

```yaml
# 새로 지원하는 형식
ip_feed_url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
domain_feed_url: https://urlhaus.abuse.ch/downloads/text_online/
hash_db_path: config/known_hashes.txt
feed_update_hours: 6
```

파서 확장 로직:
```cpp
size_t colon = t.find(':');
if (colon != std::string::npos && colon + 1 < t.size()) {
    std::string val = trim(t.substr(colon + 1));
    if (!val.empty() && val[0] != '#') {
        /* 스칼라 값 처리 */
        if (key == "ip_feed_url") ip_feed_url = val;
        ...
        continue;
    }
}
/* 콜론 이후 비어있으면 섹션 헤더로 처리 */
```

---

## 3. 새로운 탐지 룰 요약

| 룰 ID | 이름 | 심각도 | 피드 소스 |
|---|---|---|---|
| R-025 | 알려진 C2 서버 IP 연결 | critical | Feodo Tracker |
| R-026 | 악성 도메인 DNS 조회 | critical | URLhaus |
| R-027 | 알려진 악성 파일 해시 실행 | critical | MalwareBazaar (known_hashes.txt) |

---

## 4. 다음 목표

- **EWMA 행동 이상 탐지 (R-028)**: 프로세스별 네트워크 연결·파일 쓰기·exec 빈도를 지수 가중 이동 평균으로 추적, Z-점수 임계값(3.0) 초과 시 이상 탐지
