# 주차별 진행 보고서

**프로젝트명:** 가벼운 리눅스용 EDR(Endpoint Detection & Response) 시스템  
**담당 파트:** 에이전트(Agent) 개발  
**작성일:** 2026-05-08  
**작성자:** (본인 이름)

---

## 1. 개요

5주차에는 파일리스(Fileless) 공격 탐지를 더욱 정교화하고, 네트워크 계층의 DNS 모니터링을 추가하였으며, 여러 이벤트를 시간 축 위에서 연결하는 **이벤트 상관 분석 엔진**을 새롭게 구현하였다.

구체적인 구현 내용은 다음과 같다.

1. **memfd_create() 탐지 (R-017)**: 파일리스 셸코드 드로퍼의 핵심 syscall 감시
2. **DNS 쿼리 모니터링 (R-018a/b/c)**: BPF 내부 DNS 와이어 포맷 파싱 + DGA·터널링 탐지
3. **이벤트 상관 분석 엔진 (R-019~R-023)**: 슬라이딩 윈도우 기반 다단계 공격 패턴 탐지

---

## 2. 구현 내용

### 2.1 memfd_create() 파일리스 공격 탐지 (R-017)

#### 2.1.1 배경

`memfd_create()`는 파일시스템에 흔적을 남기지 않는 익명(anonymous) 파일 디스크립터를 생성하는 syscall이다. 공격자는 다음 순서로 이를 악용한다.

```
memfd_create("", MFD_ALLOW_SEALING)   ← 익명 파일 생성 (흔적 없음)
  → write(fd, shellcode, len)         ← 셸코드 삽입
  → fexecve(fd, argv, envp)           ← 파일 없이 실행
```

디스크에 악성 파일이 존재하지 않으므로 기존 파일 기반 스캐너로는 탐지가 불가능하다.

#### 2.1.2 구현

`memory_monitor.bpf.c`에 `sys_enter_memfd_create` 트레이스포인트 훅을 추가하고, `memfd_event` 구조체를 링버퍼로 전송한다. `name` 인자(사람이 읽는 레이블)와 `flags`(MFD_CLOEXEC, MFD_ALLOW_SEALING)를 함께 캡처한다.

```c
SEC("tp/syscalls/sys_enter_memfd_create")
int handle_memfd(struct trace_event_raw_sys_enter *ctx)
{
    struct memfd_event *e = bpf_ringbuf_reserve(&rb_memfd, sizeof(*e), 0);
    if (!e) return 0;

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xffffffff;
    e->flags = (__u32)ctx->args[1];
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

유저스페이스 룰 엔진(R-017)의 판단 기준:

| 조건 | 심각도 | 근거 |
|---|---|---|
| `name == ""` (빈 레이블) | **critical** | 추적 회피 의도 명확 |
| `MFD_ALLOW_SEALING` 플래그 설정 | **critical** | 쓰기 후 불변 밀봉 = 셸코드 완성 지표 |
| 그 외 memfd_create | **high** | 파일리스 패턴이지만 JIT 런타임 가능성 존재 |

Java JVM, Node.js V8, QEMU, Firefox 등 memfd_create를 정상적으로 사용하는 런타임은 화이트리스트로 제외한다.

---

### 2.2 DNS 쿼리 모니터링 (R-018)

#### 2.2.1 설계 결정: BPF 내부 파싱 vs. 유저스페이스 파싱

DNS 패킷은 UDP 포트 53으로 나가는 `sendto()` syscall을 통해 감시할 수 있다. 파싱 위치의 트레이드오프:

| | BPF 내부 파싱 | 유저스페이스 파싱 |
|---|---|---|
| 성능 | 커널에서 처리 후 소량 데이터만 전송 | 원본 패킷 전체 전송 필요 |
| 구현 난이도 | 높음 (Verifier 제약) | 낮음 |
| 교육적 가치 | 높음 (BPF 바운드 루프 학습) | 낮음 |

학습 목적을 고려해 BPF 내부에서 직접 QNAME을 파싱하는 방식을 채택하였다.

#### 2.2.2 BPF DNS QNAME 파싱

DNS 와이어 포맷의 QNAME은 길이-레이블 시퀀스로 구성된다.

```
\x03www\x06google\x03com\x00  →  "www.google.com"
```

BPF Verifier는 동적 배열 인덱스(변수 오프셋 접근)를 거부하므로, **AND 마스크 패턴**으로 경계를 정적으로 증명해야 한다.

```c
#define DNS_BUF_LEN 128  /* BPF 검증기를 위해 반드시 2의 거듭제곱 */

/* BPF 검증기에게 경계 증명: raw[pos & 127]은 항상 [0, 127] 범위 */
__u8 label_len = raw[pos & (DNS_BUF_LEN - 1)];

/* 출력 버퍼도 동일하게 AND 마스킹 */
e->name[out & (DNS_NAME_MAX - 1)] = '.';
```

BPF 바운드 루프(#pragma unroll 없이 최대 반복 제한)로 외부 루프 10개 레이블, 내부 루프 63자를 파싱한다.

#### 2.2.3 탐지 룰

| 룰 ID | 조건 | 심각도 | 공격 패턴 |
|---|---|---|---|
| R-018a | 레이블 길이 > 50자 | critical | DNS 터널링 (iodine, dnscat2) |
| R-018b | 첫 레이블 > 15자 AND 모음 비율 < 0.15 | high | DGA(Domain Generation Algorithm) |
| R-018c | .tk/.ml/.ga/.cf/.gq/.xyz 등 남용 TLD | medium | C2 서버 피싱 도메인 |

`systemd-resolved`, `avahi-daemon` 등 시스템 DNS 데몬은 화이트리스트로 제외한다. DNS 이벤트는 빈도가 매우 높으므로(브라우저 단독으로 수백 건/분), 알림이 없는 이벤트는 stdout 출력을 생략해 노이즈를 줄였다.

---

### 2.3 이벤트 상관 분석 엔진 (R-019~R-023)

#### 2.3.1 단일 이벤트 탐지의 한계

단일 syscall 이벤트만으로는 오탐(FP) 비율이 높다.

- `ptrace(ATTACH)` 단독: 합법적 디버거(gdb, strace) 가능성
- `memfd_create()` 단독: JVM, V8 등 JIT 런타임 가능성
- `connect()` 단독: 대부분 정상 트래픽

그러나 **같은 프로세스에서 30~60초 이내에 두 이벤트가 연달아 발생**하면 공격 신뢰도가 크게 올라간다.

#### 2.3.2 구현: 슬라이딩 윈도우 히스토리

`CorrelationEngine` 클래스(슬라이딩 윈도우 방식)를 새로 구현하였다.

```
PID 별 deque<Record>  ←  evict(60s 초과 항목 제거)
                      ↑
           feed(pid, CorrelEvt::PTRACE, ts_ns)
                      │
           1. 기존 히스토리에서 패턴 매칭  ← 새 이벤트 추가 전!
           2. hits 수집
           3. 새 이벤트를 deque에 추가
           4. hits 반환
```

자기 자신과의 매칭을 방지하기 위해 **패턴 체크 후 이벤트를 추가**하는 순서가 핵심이다.

추상화된 이벤트 종류(`CorrelEvt`):

```cpp
enum class CorrelEvt : uint8_t {
    EXEC_TMP  = 1,  // /tmp, /dev/shm 실행
    WRITE_TMP = 2,  // /tmp 쓰기
    NET_CONN  = 3,  // 아웃바운드 connect()
    PTRACE    = 4,  // ptrace ATTACH/SEIZE
    MEM_RWX   = 5,  // mmap/mprotect PROT_WRITE|EXEC
    MEMFD     = 6,  // memfd_create()
    DNS_SUSP  = 7,  // R-018 발화 의심 DNS 쿼리
};
```

#### 2.3.3 탐지 패턴

| 룰 ID | 패턴 | 윈도우 | 심각도 | 공격 시나리오 |
|---|---|---|---|---|
| R-019 | PTRACE ↔ MEMFD | 30초 | critical | 프로세스 인젝션 체인 |
| R-020 | EXEC_TMP ↔ NET_CONN | 60초 | critical | 드로퍼 + C2 콜백 |
| R-021 | WRITE_TMP → EXEC_TMP | 60초 | critical | 다운로드+실행 |
| R-022 | MEM_RWX ↔ NET_CONN | 30초 | critical | 파일리스 C2 비콘 |
| R-023 | DNS_SUSP ↔ NET_CONN | 30초 | high | DGA 도메인 조회 후 연결 |

상관 패턴이 완성되면 `[CORRL]` 헤더로 자홍색 강조 출력하고, `type="correlation"` JSON으로 별도 직렬화한다.

---

## 3. 검증

### 3.1 memfd_create 탐지 검증

```bash
# Python으로 memfd_create 직접 호출
python3 -c "
import ctypes, os
libc = ctypes.CDLL('libc.so.6')
fd = libc.syscall(319, b'', 2)  # sys_memfd_create, name='', MFD_ALLOW_SEALING
print(f'memfd fd={fd}')
"
```

→ `[MEMFD] PID=... python3 name=(empty) flags=0x2` 출력 + R-017 critical 알림

### 3.2 상관 분석 검증

```bash
# 01_ldpreload.sh: LD_PRELOAD → /tmp 실행
# 02_fileless.sh:  memfd_create → mmap(RWX) → net connect
# 04_ptrace.sh:    ptrace(ATTACH) + memfd_create (R-019 트리거)
bash demo/04_ptrace.sh
```

→ `[CORRL] ... ▶ 상관 패턴 탐지` + R-019 critical 알림

---

## 4. 다음 목표

1. **컨테이너 탈출 탐지**: `unshare()` + PID 네임스페이스 inum 비교로 컨테이너 내부 네임스페이스 분리 감지 (R-024)
2. **룰 외부화**: YAML 파일로 화이트리스트/블랙리스트를 런타임에 교체 가능하게 구조 개선
