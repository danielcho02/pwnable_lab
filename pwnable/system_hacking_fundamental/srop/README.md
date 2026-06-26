# 🧠 SigReturn-Oriented Programming

## 📌 Definition
- NX = shellcode의 실행 방지
- RTL = shellcode를 이용하지 않고 libc의 함수를 호출에 보호기법을 우회
- ROP = 프로그램의 코드를 재활용, gadget을 이어 붙여 임의 함수를 연속해서 호출
- SROP = context switching을 위해 사용하는 sigreturn system call을 이용한 ROP 기법
---

## 📄 Signal
프로세스에 특정 정보를 전달하는 매게체
시그널 발생 → 시그널에 해당하는 코드가 커널 모드에서 실행 → 다시 유저 모드로 복귀
유저 모드로 복귀해서 프로세스의 코드를 실행해야함 = 유저 모드의 상태를 기억해야함
`do_signal` = 시그널을 처리하기 위해 제일 먼저 호출되는 함수
`get_signal` = 시그널에 해당하는 핸들러가 등록되어 있는지 확인, 시그널에 대한 정보와 레지스터 정보를 인자로 핸들러 호출
`handle_signal` = `SIGALRM`이 발생할 경우 핸들러의 주소를 다음 실행 주소로 삽입
```bash
regs->si = (unsigned long)&frame->info;
regs->dx = (unsigned long)&frame->uc;
regs->ip = (unsigned long) ksig->ka.sa.sa_handler;
regs->sp = (unsigned long)frame;
```
---

## 📄 sigreturn
`Context switching` = 현재 프로세스가 바뀌는 것, 커널 모드에서 프로세스 실행 후 다시 유저모드로 복귀
`sigreturn` = context switching이 일어날 때 상태를 기억하고 커널 코드의 실행을 마치면 기억한 정보

---

## 📄 sigcontext
x86_64 아키텍처에 해당하는 구조체
```c
/* __x86_64__: */
struct sigcontext {
  __u64               r8;
  __u64               r9;
  __u64               r10;
  __u64               r11;
  __u64               r12;
  __u64               r13;
  __u64               r14;
  __u64               r15;
  __u64               rdi;
  __u64               rsi;
  __u64               rbp;
  __u64               rbx;
  __u64               rdx;
  __u64               rax;
  __u64               rcx;
  __u64               rsp;
  __u64               rip;
  __u64               eflags;     /* RFLAGS */
  __u16               cs;
  __u16               gs;
  __u16               fs;
  union {
      __u16           ss; /* If UC_SIGCONTEXT_SS */
      __u16           __pad0; /* Alias name for old (!UC_SIGCONTEXT_SS) user-space */
  };
  __u64               err;
  __u64               trapno;
  __u64               oldmask;
  __u64               cr2;
  struct _fpstate __user      *fpstate;   /* Zero when no FPU context */
#  ifdef __ILP32__
  __u32               __fpstate_pad;
#  endif
  __u64               reserved1[8];
};
```

---

## 🗡️ Bypass / Exploitation
```c
// Name: sigrt_call.c
// Compile: gcc -o sigrt_call sigrt_call.c 
#include <string.h>

int main()
{
        char buf[1024];
        memset(buf, 0x41, sizeof(buf));

        asm("mov $15, %rax;"
            "syscall");
}
```
```bash
$ gdb -q ./sigrt_call
gdb-peda$ r
Starting program: sigrt_call 

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x4141414141414141 ('AAAAAAAA')
RCX: 0x4141414141414141 ('AAAAAAAA')
RDX: 0x4141414141414141 ('AAAAAAAA')
RSI: 0x4141414141414141 ('AAAAAAAA')
RDI: 0x4141414141414141 ('AAAAAAAA')
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x4141414141414141 ('AAAAAAAA')
RIP: 0x4141414141414141 ('AAAAAAAA')
R8 : 0x4141414141414141 ('AAAAAAAA')
R9 : 0x4141414141414141 ('AAAAAAAA')
R10: 0x4141414141414141 ('AAAAAAAA')
R11: 0x4141414141414141 ('AAAAAAAA')
R12: 0x4141414141414141 ('AAAAAAAA')
R13: 0x4141414141414141 ('AAAAAAAA')
R14: 0x4141414141414141 ('AAAAAAAA')
R15: 0x4141414141414141 ('AAAAAAAA')
EFLAGS: 0x10343 (CARRY parity adjust ZERO sign TRAP INTERRUPT direction overflow)
```

---

## ✅ Key Takeaways
