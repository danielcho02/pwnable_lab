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


---

## 📄 
---

## 📄 


---

## 🗡️ Bypass / Exploitation


---

## ✅ Key Takeaways

