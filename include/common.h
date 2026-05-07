/*
 * common.h - BPF 커널 프로그램과 유저스페이스가 공유하는 데이터 구조
 *
 * include 위치:
 *   1. bpf/process_monitor.bpf.c  (커널 BPF 컨텍스트)
 *   2. bpf/file_monitor.bpf.c     (커널 BPF 컨텍스트)
 *   3. src/main.cpp               (유저스페이스)
 */
#ifndef EDR_COMMON_H
#define EDR_COMMON_H

/*
 * __u8/__u16/__u32/__u64 타입 공급원:
 *   BPF 커널 컨텍스트 (-target bpf): bpf_helpers.h 가 이미 정의.
 *   유저스페이스 (g++/clang++):       <linux/types.h> 에서 공급.
 *
 * clang은 -target bpf 컴파일 시 __BPF__ 매크로를 자동 정의한다.
 */
#ifndef __BPF__
#  include <linux/types.h>
#endif

/* ── 공통 상수 ────────────────────────────────────────────────────────── */

/* kernel/sched.h: task_struct.comm 최대 길이 (15글자 + NUL) */
#define TASK_COMM_LEN    16

/* execve() 경로 저장 한도: BPF 스택(512B) 제약으로 256 사용 */
#define MAX_FILENAME_LEN 256

/* 파일 경로 저장 한도: 링버퍼 슬롯에서 할당하므로 256 사용 */
#define MAX_PATH_LEN     256

/*
 * argv 캡처 상수 (sys_enter_execve 훅에서 사용):
 *
 *   MAX_ARGV_LEN: NUL 구분 argv 연결 버퍼 크기.
 *                 /proc/<pid>/cmdline 과 동일한 형식으로 저장.
 *                 링버퍼 슬롯에 할당되므로 스택 제약 없음.
 *
 *   MAX_ARGC:     캡처할 최대 인자 수. BPF 검증기(verifier)가
 *                 #pragma unroll 루프를 정적으로 분석하기 위해 상수 필요.
 */
#define MAX_ARGV_LEN 256
#define MAX_ARGC       8

/*
 * DNS 모니터링 상수 (dns_monitor.bpf.c / rule_engine):
 *
 *   DNS_NAME_MAX: 파싱된 도메인명 저장 길이.
 *                 RFC 1035 최대치는 253자지만 128로 충분히 커버된다.
 *                 BPF 검증기 AND 마스크 패턴을 위해 2의 거듭제곱으로 유지.
 */
#define DNS_NAME_MAX 128

/* ── 이벤트 타입 ─────────────────────────────────────────────────────── */

/*
 * 각 BPF 프로그램이 링버퍼에 기록하는 이벤트의 종류.
 * 유저스페이스에서 이 값으로 핸들러를 분기한다.
 */
#define EVENT_PROC_EXEC   1u  /* sched_process_exec: execve() 성공           */
#define EVENT_FILE_WRITE  2u  /* sys_enter_openat: O_WRONLY/O_RDWR/O_CREAT   */
#define EVENT_FILE_DELETE 3u  /* sys_enter_unlinkat: unlink()/unlinkat()      */
#define EVENT_FILE_RENAME 4u  /* sys_enter_renameat2: rename()/renameat2()   */
#define EVENT_NET_CONNECT 5u  /* sys_enter_connect: 아웃바운드 연결 시도     */
#define EVENT_NET_BIND    6u  /* sys_enter_bind: 포트 바인드(서버 오픈)      */
#define EVENT_PROC_EXIT   7u  /* sched_process_exit: 프로세스 정상 종료      */
#define EVENT_PROC_PTRACE 8u  /* sys_enter_ptrace: ptrace ATTACH 감지        */
#define EVENT_PROC_MEMFD  9u  /* sys_enter_memfd_create: 익명 파일 생성      */
#define EVENT_PROC_NS    10u  /* sys_enter_unshare: 네임스페이스 분리 시도   */

/* ── 구조체 정의 ─────────────────────────────────────────────────────── */

/*
 * process_event: sched_process_exec 트레이스포인트에서 캡처.
 * execve() 가 새 바이너리를 VAS 에 매핑한 직후 발화하므로
 * 실패한 exec 는 포함되지 않는다.
 *
 * argv / argc 채우기 경로:
 *   1. sys_enter_execve BPF 훅에서 argv[] 를 읽어 argv_store 맵에 임시 저장.
 *   2. sched_process_exec BPF 훅에서 argv_store 를 조회·복사 후 맵에서 삭제.
 *   argc == 0 이면 캡처 실패(exec 경쟁, execveat 경유 등).
 */
struct process_event {
    __u32 pid;                        /* 유저스페이스 PID = 커널 TGID        */
    __u32 ppid;                       /* 부모 프로세스 ID (real_parent.tgid) */
    __u32 uid;                        /* 실UID (real uid)                    */
    __u32 argc;                       /* 캡처된 argv 인자 수 (0 = 미캡처)   */
    __u64 ts_ns;                      /* bpf_ktime_get_ns(): 부팅 이후 ns    */
    char  comm[TASK_COMM_LEN];        /* task_struct.comm (basename)         */
    char  filename[MAX_FILENAME_LEN]; /* execve() 에 전달된 실행 파일 경로   */
    char  argv[MAX_ARGV_LEN];         /* argv 연결 버퍼: NUL 구분, cmdline 형식 */
    __u32 euid;                       /* 실효 UID (R-015: uid≠euid → setuid 실행) */
    __u8  has_ld_preload;             /* 1 if envp 에 LD_PRELOAD= 포함 (R-013) */
    __u8  _pad2[3];                   /* 구조체 정렬 패딩 */
};

/*
 * file_event: 파일시스템 조작 이벤트.
 *
 *   type == EVENT_FILE_WRITE:
 *     path  = openat()에 전달된 경로
 *     path2 = ""  (미사용)
 *     flags = openat flags (O_WRONLY | O_CREAT | ...)
 *
 *   type == EVENT_FILE_DELETE:
 *     path  = unlinkat()에 전달된 경로
 *     path2 = ""  (미사용)
 *     flags = unlinkat flags (AT_REMOVEDIR 등)
 *
 *   type == EVENT_FILE_RENAME:
 *     path  = 원본 경로 (oldpath)
 *     path2 = 대상 경로 (newpath)
 *     flags = renameat2 flags
 *
 * path/path2 는 syscall 인자에서 직접 읽은 유저스페이스 문자열이므로
 * 상대 경로일 수 있다 (dirfd 기반). 절대 경로 해석은 프로덕션에서 추가.
 */
struct file_event {
    __u32 type;                   /* EVENT_FILE_* 상수                  */
    __u32 pid;                    /* 유저스페이스 PID                   */
    __u32 uid;                    /* 실효 UID                           */
    __u32 flags;                  /* 해당 syscall의 flags 인자          */
    __u64 ts_ns;                  /* bpf_ktime_get_ns()                 */
    char  comm[TASK_COMM_LEN];    /* task_struct.comm                   */
    char  path[MAX_PATH_LEN];     /* 주 경로 (원본 또는 대상)           */
    char  path2[MAX_PATH_LEN];    /* 보조 경로 (rename 대상)            */
};

/*
 * net_event: 네트워크 연결/바인드 이벤트.
 *
 *   type == EVENT_NET_CONNECT:
 *     connect() 시스템 콜 진입 시점의 스냅샷.
 *     연결 성공 여부는 반환값(sys_exit_connect)에서 확인 가능 (PoC에선 생략).
 *     daddr/dport = 상대방 IP/포트.
 *
 *   type == EVENT_NET_BIND:
 *     bind() 시스템 콜 진입 시점. 프로세스가 서버 소켓을 여는 순간.
 *     daddr/dport = 바인드할 로컬 IP/포트.
 *
 * daddr[16]: IPv4는 앞 4바이트만 사용, IPv6는 16바이트 전체 사용.
 * dport: 네트워크 바이트 오더(big-endian). 유저스페이스에서 ntohs() 필요.
 */
struct net_event {
    __u32 type;                /* EVENT_NET_CONNECT or EVENT_NET_BIND    */
    __u32 pid;                 /* 유저스페이스 PID                       */
    __u32 uid;                 /* 실효 UID                               */
    __u16 family;              /* AF_INET(2) or AF_INET6(10)             */
    __u16 dport;               /* 대상/로컬 포트 (network byte order)    */
    __u64 ts_ns;               /* bpf_ktime_get_ns()                     */
    char  comm[TASK_COMM_LEN]; /* task_struct.comm                       */
    __u8  daddr[16];           /* 대상/로컬 IP 주소                      */
};

/*
 * ptrace_event: ptrace() ATTACH 이벤트.
 *
 * sys_enter_ptrace 트레이스포인트에서 PTRACE_ATTACH/PTRACE_SEIZE 요청만 캡처.
 * 프로세스 인젝션(PTRACE_POKEDATA) 이나 디버거 탐지에 사용된다.
 */
struct ptrace_event {
    __u32 pid;              /* 추적자(tracer) PID          */
    __u32 target_pid;       /* 추적 대상(tracee) PID       */
    __u32 uid;
    __u32 request;          /* PTRACE_ATTACH=16 등         */
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
};

/*
 * exit_event: 프로세스 종료 이벤트.
 *
 * sched_process_exit 트레이스포인트에서 캡처.
 * 스레드(TID != TGID) 종료는 BPF 측에서 필터링하여 프로세스 리더 종료만 전달.
 *
 * exit_code: task_struct.exit_code
 *   상위 8비트 = 정상 종료 코드 (exit(N) → exit_code = N << 8)
 *   하위 8비트 = 종료 시그널 번호 (시그널 종료 시)
 */
struct exit_event {
    __u32 pid;
    __u32 exit_code;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
};

/*
 * memory_event: mmap / mprotect 로 RWX 메모리 할당 (R-016).
 *
 * sys_enter_mmap 및 sys_enter_mprotect 훅에서 캡처.
 * prot 인자에 PROT_EXEC(4) 와 PROT_WRITE(2) 가 모두 포함된 경우만 기록.
 */
struct memory_event {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    __u32 prot;         /* 요청된 권한 플래그 */
    __u32 is_mprotect;  /* 0: mmap, 1: mprotect */
};

/*
 * dns_event: DNS 쿼리 이벤트 (R-018).
 *
 * sys_enter_sendto 훅에서 UDP 포트 53 패킷을 감지하고,
 * BPF 내에서 DNS 와이어 포맷 QNAME 을 점 구분 문자열로 파싱해 저장한다.
 *
 *   server[16]: DNS 서버 IP (IPv4 = 앞 4바이트, 나머지 0)
 *   name:       "www.google.com" 형식의 파싱된 도메인명
 */
struct dns_event {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN]; /* 16 bytes */
    __u8  server[16];          /* DNS 서버 IP */
    __u16 family;              /* AF_INET(2) / AF_INET6(10) */
    __u16 _pad;
    char  name[DNS_NAME_MAX];  /* 파싱된 도메인명 */
};

/*
 * memfd_event: memfd_create() 익명 파일 생성 이벤트 (R-017).
 *
 * memfd_create()는 파일시스템에 이름이 없는 익명 파일 디스크립터를 생성한다.
 * 파일리스 공격에서 다음 패턴으로 악용된다:
 *   memfd_create() → write(셸코드) → fexecve(fd)
 *
 * name: 사람이 읽는 레이블 (경로가 아님). 빈 문자열("") 이면 더 의심스럽다.
 * flags: MFD_CLOEXEC=0x1, MFD_ALLOW_SEALING=0x2 (밀봉된 불변 코드 → critical)
 */
struct memfd_event {
    __u32 pid;
    __u32 uid;
    __u32 flags;              /* MFD_* 플래그 조합 */
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    char  name[64];           /* memfd_create() 의 name 인자 (레이블) */
};

/*
 * ns_event: 네임스페이스 분리(unshare) 이벤트 (R-024).
 *
 * sys_enter_unshare 트레이스포인트에서 CLONE_NEW* 플래그를 포함한 호출만 캡처.
 * 컨테이너 내부에서의 네임스페이스 분리는 탈출 시도의 핵심 지표다.
 *
 * in_container: BPF 에서 현재 PID 네임스페이스 inum 을 init 네임스페이스와
 *               비교해 결정. 1 이면 컨테이너(또는 다른 네임스페이스) 내부.
 * ns_inum:      현재 PID 네임스페이스의 inode 번호 (커널 nsproxy 에서 읽음).
 * flags:        unshare() 에 전달된 CLONE_NEW* 플래그 조합.
 */
struct ns_event {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    __u32 flags;         /* CLONE_NEW* 플래그 조합                    */
    __u8  in_container;  /* 1 = 현재 PID 네임스페이스 ≠ init 네임스페이스 */
    __u8  _pad[3];
    __u64 ns_inum;       /* 현재 PID 네임스페이스 inode 번호           */
};

#endif /* EDR_COMMON_H */
