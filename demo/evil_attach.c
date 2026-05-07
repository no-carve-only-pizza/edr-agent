/*
 * evil_attach.c - ptrace ATTACH 데모 헬퍼 (R-014 트리거용)
 *
 * gdb/strace 는 PTRACE_WHITELIST 에 있어 알림이 발화하지 않는다.
 * 이 바이너리("evil_attach")는 화이트리스트에 없으므로 R-014 를 발화시킨다.
 *
 * 실제 공격 도구가 아님 - attach 후 즉시 detach 한다.
 * 권한 없는 PID 에 attach 하면 EPERM 으로 실패하지만 BPF 훅은 시도 자체를 잡는다.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <대상 PID>\n", argv[0]);
        return 1;
    }

    pid_t target = (pid_t)atoi(argv[1]);
    printf("[evil_attach] ptrace(PTRACE_ATTACH, %d) 시도...\n", target);

    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
        /* EPERM 은 정상 — BPF 훅이 시도 자체를 이미 캡처했다 */
        printf("[evil_attach] 실패: %s (BPF 이벤트는 이미 전송됨)\n",
               strerror(errno));
        return 0;
    }

    waitpid(target, NULL, 0);
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    printf("[evil_attach] attach/detach 완료\n");
    return 0;
}
