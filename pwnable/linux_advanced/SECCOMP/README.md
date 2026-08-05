# 🧠 SECCOMP(SECure COMPuting mode)

## 📌 Definition
`원격 코드 실행(Remote Code Execution)` 취약점은 사전에 예방할 수 없음
`샌드박스(Sandbox)` = 외부의 공격으로부터 시스템을 보호하기 위해 설계된 기법
`Allow List`와 `Deny List` 선택 적용 = 보호된 영역에서 어플리케이션 기능 수행, 외부의 공격 최소화
`SECCOMP` = Linux Kernel에서 프로그램의 샌드박싱 매커니즘을 제공, 불필요한 syscall 호출 방지

---

## 📄 STRICT_MODE
`read`, `write`, `exit`, `sigreturn` system call 호출만 허용
이외는 `SIGKILL` 시그널 발생, 프로그램 종료

```c
static const int mode1_syscalls[] = {
    __NR_seccomp_read,
    __NR_seccomp_write,
    __NR_seccomp_exit,
    __NR_seccomp_sigreturn,
    -1, /* negative terminated */
};
#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
    __NR_seccomp_read_32,
    __NR_seccomp_write_32,
    __NR_seccomp_exit_32,
    __NR_seccomp_sigreturn_32,
    0, /* null terminated */
};
#endif
static void __secure_computing_strict(int this_syscall) {
  const int *allowed_syscalls = mode1_syscalls;
#ifdef CONFIG_COMPAT
  if (in_compat_syscall()) allowed_syscalls = get_compat_mode1_syscalls();
#endif
  do {
    if (*allowed_syscalls == this_syscall) return;
  } while (*++allowed_syscalls != -1);
#ifdef SECCOMP_DEBUG
  dump_stack();
#endif
  seccomp_log(this_syscall, SIGKILL, SECCOMP_RET_KILL_THREAD, true);
  do_exit(SIGKILL);
}
```
`mode1_syscalls[]`는 `read`, `write`, `exit`, `sigreturn` system call의 번호를 저장하고 있는 변수
이후에 어플리케이션에서 시스템 콜이 호출되면 `__secure_computing`함수에 먼저 진입
`mode1_syscalls` 혹은 `mode1_syscalls_32`에 미리 정의된 번호와 일치하는지 검사
일치하지 않는다면, `SIGKILL` 시그널을 전달, `SECCOMP_RET_KILL`을 반환

---

## 📄 FILTER_MODE
원하는 시스템 콜의 호출을 허용하거나 거부할 수 있음
`seccomp_init` = SECCOMP 모드의 기본값을 설정
`seccomp_rule_add` = 규칙 추가
`seccomp_load` = 적용한 규칙을 어플리케이션에 반영

### 1. ALLOW LIST
```c
// Name: libseccomp_alist.c
// Compile: gcc -o libseccomp_alist libseccomp_alist.c -lseccomp
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  if (ctx == NULL) {
    printf("seccomp error\n");
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  seccomp_load(ctx);
}
int banned() { fork(); }
int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  if (argc < 2) {
    banned();
  }
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}
```
`SCMP_ACT_KILL`을 통해 모든 시스템 콜의 호출을 허용하지 않는 규칙을 생성
`seccomp_rule_add`를 통해 ALLOW LIST를 생성

### 2. DENY LIST
```c
// Name: libseccomp_dlist.c
// Compile: gcc -o libseccomp_dlist libseccomp_dlist.c -lseccomp
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 0);
  seccomp_load(ctx);
}
int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}
```
ALLOW LIST와 반대로 `SCMP_ACT_ALLOW`로 모든 시스템 콜의 호출을 허용하는 규칙 생성
`seccomp_rule_add`로 세 번째 인자로 전달된 시스템 콜의 호출을 거부하는 규칙을 생성

---

## 📄 BPF(Berkeley Packet Filter)
BPF = 커널에서 지원하는 VM
임의 데이터를 비교, 결과에 따라 특정 구문으로 분기하는 명령어를 제공
`BPF_LD` = 인자로 전달된 값을 누산기에 복사
`BPF_JMP` = 저장한 위치로 분기
`BPF_JEQ` = 설정한 비교 구문이 일치할 경우 지정한 위치로 분기
`BPF_RET` = 인자로 전달된 값을 반환

```c
// Name: secbpf_alist.c
// Compile: gcc -o secbpf_alist secbpf_alist.c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#define ALLOW_SYSCALL(name)                               \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64
int sandbox() {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      ALLOW_SYSCALL(rt_sigreturn),
      ALLOW_SYSCALL(open),
      ALLOW_SYSCALL(openat),
      ALLOW_SYSCALL(read),
      ALLOW_SYSCALL(write),
      ALLOW_SYSCALL(exit_group),
      KILL_PROCESS,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("Seccomp filter error\n");
    return -1;
  }
  return 0;
}
void banned() { fork(); }
int main(int argc, char* argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  if (argc < 2) {
    banned();
  }
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}
```
```c
// Name: secbpf_dlist.c
// Compile: gcc -o secbpf_dlist secbpf_dlist.c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#define DENY_SYSCALL(name)                                \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64
int sandbox() {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      DENY_SYSCALL(open),
      DENY_SYSCALL(openat),
      MAINTAIN_PROCESS,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("Seccomp filter error\n");
    return -1;
  }
  return 0;
}
int main(int argc, char* argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}
```
ALLOW LIST와 DENY LIST는 위와 같이 구현한다.

---

## ✅ Key Takeaways
SECCOMP는 리눅스에서 프로그램이 사용할 수 있는 시스템 콜을 제한하는 샌드박스 기능이다. STRICT MODE는 `read`, `write`, `exit`, `sigreturn`만 허용하고, FILTER MODE는 Allow List나 Deny List 방식으로 필요한 시스템 콜을 직접 허용하거나 차단한다. 이를 통해 취약점이 발생하더라도 공격자가 실행할 수 있는 기능을 줄여 피해를 최소화할 수 있다.
