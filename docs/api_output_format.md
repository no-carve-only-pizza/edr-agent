# EDR Agent — NDJSON 출력 포맷 명세

에이전트가 `--log <파일>` 옵션으로 기록하는 NDJSON(Newline-Delimited JSON) 포맷입니다.  
한 줄 = 이벤트 1건. 줄 끝에 `\n`.

---

## 공통 필드

모든 이벤트에 반드시 포함되는 필드입니다.

| 필드 | 타입 | 설명 |
|------|------|------|
| `type` | string | 이벤트 종류 (아래 참고) |
| `ts` | number | 부팅 이후 경과 시간(초, 소수점 3자리) |
| `pid` | number | 이벤트 발생 프로세스 PID |
| `uid` | number | 실제 UID (0 = root) |
| `comm` | string | 프로세스 이름 (최대 15자, 커널 제한) |
| `alerts` | array | 탐지된 룰 목록 (없으면 `[]`) |

**alerts 배열 구조:**
```json
[
  {
    "id":   "R-001",
    "name": "민감 경로 파일 수정",
    "sev":  "high"
  }
]
```

`sev` 값: `"critical"` / `"high"` / `"medium"` / `"low"`

---

## 이벤트 타입별 포맷

### 1. `exec` — 프로세스 실행

```json
{
  "type":       "exec",
  "ts":         12345.678,
  "pid":        1234,
  "ppid":       1000,
  "uid":        1000,
  "comm":       "bash",
  "path":       "/usr/bin/bash",
  "argv":       ["bash", "-c", "id"],
  "euid":       0,
  "ld_preload": false,
  "alerts":     []
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `ppid` | number | 부모 프로세스 PID |
| `path` | string | 실행 파일 전체 경로 |
| `argv` | array | 실행 인자 목록 |
| `euid` | number | 유효 UID (uid != euid → setuid 실행) |
| `ld_preload` | boolean | `LD_PRELOAD` 환경변수 존재 여부 |

---

### 2. `file_write` / `file_delete` / `file_rename` — 파일 접근

```json
{
  "type":   "file_write",
  "ts":     12345.678,
  "pid":    1234,
  "uid":    1000,
  "comm":   "vim",
  "path":   "/etc/passwd",
  "flags":  33,
  "alerts": [{"id":"R-001","name":"민감 경로 파일 수정","sev":"high"}]
}
```

```json
{
  "type":   "file_rename",
  "ts":     12345.678,
  "pid":    1234,
  "uid":    0,
  "comm":   "mv",
  "path":   "/tmp/evil",
  "dst":    "/usr/bin/evil",
  "flags":  0,
  "alerts": []
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `path` | string | 원본 파일 경로 |
| `dst` | string | 이동 대상 경로 (`file_rename`에만 포함) |
| `flags` | number | 커널 open 플래그 (raw) |

---

### 3. `net_connect` / `net_bind` — 네트워크

```json
{
  "type":   "net_connect",
  "ts":     12345.678,
  "pid":    1234,
  "uid":    1000,
  "comm":   "curl",
  "dst":    "203.0.113.1",
  "dport":  4444,
  "family": "ipv4",
  "alerts": [{"id":"R-006","name":"비표준 포트 아웃바운드","sev":"medium"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `dst` | string | 목적지 IP 주소 |
| `dport` | number | 목적지 포트 |
| `family` | string | `"ipv4"` 또는 `"ipv6"` |

---

### 4. `dns` — DNS 쿼리

```json
{
  "type":   "dns",
  "ts":     12345.678,
  "pid":    1234,
  "uid":    1000,
  "comm":   "curl",
  "query":  "evil.tk",
  "server": "8.8.8.8",
  "family": "ipv4",
  "alerts": [{"id":"R-018c","name":"남용 TLD DNS 쿼리","sev":"medium"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `query` | string | 조회한 도메인명 |
| `server` | string | DNS 서버 IP |
| `family` | string | `"ipv4"` 또는 `"ipv6"` |

---

### 5. `ptrace` — 프로세스 추적/인젝션 시도

```json
{
  "type":       "ptrace",
  "ts":         12345.678,
  "pid":        1234,
  "uid":        1000,
  "comm":       "gdb",
  "target_pid": 999,
  "request":    16,
  "alerts":     [{"id":"R-014","name":"ptrace ATTACH 의심","sev":"high"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `target_pid` | number | 추적 대상 PID |
| `request` | number | ptrace request 코드 (16 = PTRACE_ATTACH) |

---

### 6. `memfd` — 메모리 기반 파일 생성 (파일리스 실행)

```json
{
  "type":    "memfd",
  "ts":      12345.678,
  "pid":     1234,
  "uid":     1000,
  "comm":    "malware",
  "name":    "payload",
  "flags":   3,
  "sealing": true,
  "alerts":  [{"id":"R-017","name":"memfd_create 파일리스 실행","sev":"high"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `name` | string | memfd 이름 (디버그용) |
| `flags` | number | memfd_create 플래그 (raw) |
| `sealing` | boolean | 쓰기 봉인 여부 |

---

### 7. `memory` — RWX 메모리 할당 (쉘코드 의심)

```json
{
  "type":        "memory",
  "ts":          12345.678,
  "pid":         1234,
  "uid":         1000,
  "comm":        "exploit",
  "prot":        7,
  "is_mprotect": false,
  "alerts":      [{"id":"R-016","name":"RWX 메모리 할당","sev":"high"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `prot` | number | 메모리 보호 플래그 (7 = RWX) |
| `is_mprotect` | boolean | `mprotect` 호출 여부 (`false`면 `mmap`) |

---

### 8. `ns_unshare` — 네임스페이스 탈출 시도

```json
{
  "type":         "ns_unshare",
  "ts":           12345.678,
  "pid":          1234,
  "uid":          1000,
  "comm":         "unshare",
  "ns_inum":      4026531836,
  "flags":        "0x10000000",
  "in_container": true,
  "alerts":       [{"id":"R-024","name":"네임스페이스 탈출 시도","sev":"high"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `ns_inum` | number | 새 네임스페이스 inode 번호 |
| `flags` | string | unshare 플래그 (hex 문자열) |
| `in_container` | boolean | 컨테이너 내부 실행 여부 |

---

### 9. `anomaly` — 행동 이상 탐지 (EWMA)

```json
{
  "type":     "anomaly",
  "ts":       12345.678,
  "comm":     "python3",
  "metric":   "net_connect",
  "observed": 87.00,
  "mean":     3.20,
  "stddev":   1.50,
  "zscore":   4.23,
  "alerts":   [{"id":"R-028","name":"행동 이상 탐지 (EWMA 기반)","sev":"high"}]
}
```

| 추가 필드 | 타입 | 설명 |
|-----------|------|------|
| `metric` | string | `"net_connect"` / `"file_write"` / `"exec"` |
| `observed` | number | 현재 윈도우(60초) 관측값 |
| `mean` | number | EWMA 기준선 평균 |
| `stddev` | number | EWMA 기준선 표준편차 |
| `zscore` | number | Z-score (3.0 초과 시 이상) |

---

## 이벤트 타입 요약

| type | 설명 |
|------|------|
| `exec` | 프로세스 실행 |
| `file_write` | 파일 쓰기 |
| `file_delete` | 파일 삭제 |
| `file_rename` | 파일 이동/이름 변경 |
| `net_connect` | 외부 TCP/UDP 연결 |
| `net_bind` | 포트 리슨(바인드) |
| `dns` | DNS 쿼리 |
| `ptrace` | 프로세스 추적 시도 |
| `memfd` | 메모리 기반 파일 생성 |
| `memory` | RWX 메모리 할당 |
| `ns_unshare` | 네임스페이스 분리 |
| `anomaly` | 행동 이상 탐지 |

---

## 사용 예시

에이전트 실행:
```bash
sudo ./edr-agent --rules config/rules.yaml --log /var/log/edr.ndjson
```

실시간 알람만 필터링:
```bash
tail -f /var/log/edr.ndjson | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e.get('alerts'):
        print(json.dumps(e, ensure_ascii=False))
"
```

타입별 집계:
```bash
cat /var/log/edr.ndjson | python3 -c "
import sys, json
from collections import Counter
c = Counter(json.loads(l)['type'] for l in sys.stdin)
for t, n in c.most_common(): print(f'{t}: {n}')
"
```
