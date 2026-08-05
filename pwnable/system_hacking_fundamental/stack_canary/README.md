# 🧠 Concept: Stack Canary <br>

## 📌 Definition <br>
함수의 프롤로그에서 Stack Buffer와 Return Adress 사이에 임의의 값을 삽입하고, 함수의 에필로그에서 해당 값의 변조를 확인하는 보호기법 <br>
Canary값의 변조가 확인되면 프로세스 강제 종료 <br>
Return Adress를 덮으려면 반드시 Canary를 먼저 덮어야 하므로 Canary 값을 모르는 공격자는 이 값을 변조 <br>


### 📄 Canary Analysis <br>
```c
// Name: canary.c

#include <unistd.h>

int main() {
  char buf[8];
  read(0, buf, 32);
  return 0;
}
```

```
$ gcc -o canary canary.c
$ ./canary
HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
*** stack smashing detected ***: <unknown> terminated
Aborted
```
Canary를 적용하여 컴파일하고 긴 입력을 주면 기존의 Segmentation fault가 아닌 stack smashing detected와 Aborted error가 발생 <br>
이는 Stack Buffer Overflow를 탐지하고 프로세스가 강제 종료되었음을 의미

```
   push   rbp
   mov    rbp,rsp
   sub    rsp,0x10
+  mov    rax,QWORD PTR fs:0x28
+  mov    QWORD PTR [rbp-0x8],rax
+  xor    eax,eax
+  lea    rax,[rbp-0x10]
-  lea    rax,[rbp-0x8]
   mov    edx,0x20
   mov    rsi,rax
   mov    edi,0x0
   call   read@plt
   mov    eax,0x0
+  mov    rcx,QWORD PTR [rbp-0x8]
+  xor    rcx,QWORD PTR fs:0x28
+  je     0x6f0 <main+70>
+  call   __stack_chk_fail@plt
   leave
   ret
```
추가된 프롤로그의 코드에 중단점 설정하고 실행<br>

```
$ gdb -q ./canary
pwndbg> break *main+8
Breakpoint 1 at 0x6b2
pwndbg> run
 ► 0x5555555546b2 <main+8>     mov    rax, qword ptr fs:[0x28] <0x5555555546aa>
   0x5555555546bb <main+17>    mov    qword ptr [rbp - 8], rax
   0x5555555546bf <main+21>    xor    eax, eax
```
main+8에서 fs:0x28의 데이터를 rax에 저장 <br>
fs는 세그먼트 레지스터의 일종으로 리눅스에서 프로세스가 시작될 때 랜덤 값을 저장 <br>
ni로 실행시, 첫 바이트가 null인 8byte 데이터가 저장되어 있음 <br>
생성한 랜덤값은 main+17에서 rbp-0x8에 저장 <br>

```
pwndbg> break *main+50
pwndbg> continue
HHHHHHHHHHHHHHHH
Breakpoint 2, 0x00000000004005c8 in main ()
 ► 0x5555555546dc <main+50>    mov    rcx, qword ptr [rbp - 8] <0x7ffff7af4191>
   0x5555555546e0 <main+54>    xor    rcx, qword ptr fs:[0x28]
   0x5555555546e9 <main+63>    je     main+70 <main+70>
    ↓
   0x5555555546f0 <main+70>    leave
   0x5555555546f1 <main+71>    ret
```
main+50은 rbp-8에 저장한 canary를 rcx로 옮기고 main+54에서 xor로 비교 <br>
-> 두 값이 동일하면 정상 반환, 다른 경우 __stack__chk_fail 호출되며 프로그램 강제 종료 <br>


### 📄 Canary Generation Process <br>
Carnary 값은 프로세스가 시작될 때, TLS에 전역변수로 저장되고, 각 함수마다 프롤로그와 에필로그에서 이 값을 참조 <br>

### TLS 주소 파악 <br>
fs는 TLS를 가리키므로 fs값을 알면 TLS의 주소를 알 수 있지만 리눅스에서 특정 system call을 사용해야만 조회하거나 설정할 수 있음 <br>
fs의 값을 설정할 때 호출되는 arch_prctl(int code, unsigned long addr)에 중단점 설정 <br>
**catch: 특정 이벤트가 발생햇을 때, 프로세스를 중지***

```
$ gdb -q ./canary
pwndbg> catch syscall arch_prctl
Catchpoint 1 (syscall 'arch_prctl' [158])
pwndbg> run
pwndbg> c
...
pwndbg> c
Continuing.

Catchpoint 1 (call to syscall arch_prctl), init_tls (naudit=naudit@entry=0) at ./elf/rtld.c:818
818 ./elf/rtld.c: No such file or directory.
...

─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0xffffffffffffffda
*RBX  0x7fffffffe090 ◂— 0x1
*RCX  0x7ffff7fe3e1f (init_tls+239) ◂— test eax, eax
*RDX  0xffff80000827feb0
*RDI  0x1002
*RSI  0x7ffff7d7f740 ◂— 0x7ffff7d7f740
...

──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x7ffff7fe3e1f     test   eax, eax
   0x7ffff7fe3e21     jne    init_tls+320
    ↓
   0x7ffff7fe3e70     lea    rsi, [rip + 0x11641]
   0x7ffff7fe3e77     lea    rdi, [rip + 0x11672]
   0x7ffff7fe3e7e     xor    eax, eax
   0x7ffff7fe3e80     call   _dl_fatal_printf                <_dl_fatal_printf>
   0x7ffff7fe3e85     nop    dword ptr [rax]
   0x7ffff7fe3e88     xor    ecx, ecx
   0x7ffff7fe3e8a     jmp    init_tls+161
   
   0x7ffff7fe3e8f     lea    rcx, [rip + 0x11be2]          <__pretty_function__.14>
   0x7ffff7fe3e96     mov    edx, 0x31b
...

pwndbg> info register $rdi
rdi            0x1002              4098
pwndbg> info register $rsi
rsi            0x7ffff7d7f740      140737351513920
pwndbg>
```
rdi 값 0x1002는 ARCH_SET_FS의 상수값 <br>
rsi 값 0x7ffff7d7f740에 TLS 저장, fs가 이를 가리킴 <br>

```
pwndbg> x/gx 0x7ffff7d7f740 + 0x28
0x7ffff7d7f768: 0x0000000000000000
pwndbg>
```
아직 어떠한 값도 설정되어 있지 않음 <br>
<br>
### Canary 값 설정
**watch: 특정 주소에 저장된 값이 변경되면 프로세스를 중단시키는 명령어**

```
pwndbg> watch *(0x7ffff7d7f740+0x28)
Hardware watchpoint 4: *(0x7ffff7d7f740+0x28)
pwndbg> continue
Continuing.

Hardware watchpoint 4: *(0x7ffff7d7f740+0x28)

Old value = 0
New value = 2005351680
security_init () at rtld.c:870
870	in rtld.c
pwndbg> x/gx 0x7ffff7d7f740+0x28
0x7ffff7d7f768:	0x8ab7f53277873d00
```
TLS+0x28의 값을 조회하면 0x8ab7f53277873d00이 Canary로 설정된 것을 확인할 수 있음<br>

### Canary우회 <br>
- 무차별 대입 (Brute Force) -> X
- TLS 접근 <br>
  TLS의 주소는 매 실행마다 바뀌지만 실행중에 TLS의 주소를 알 수 있고 임의 주소에 대한 읽기 또는 쓰기가 가능하다면 <br>
  TLS에 설정된 Canary값을 읽거나 조작 가능<br>
- Stack Canary Leak <br>
  스택 카나리를 읽을 수 있는 취약점이 있는 경우 우회 가능 <br>

```c
// Name: bypass_canary.c
// Compile: gcc -o bypass_canary bypass_canary.c

#include <stdio.h>
#include <unistd.h>

int main() {
  char memo[8];
  char name[8];
  
  printf("name : ");
  read(0, name, 64);
  printf("hello %s\n", name);
  
  printf("memo : ");
  read(0, memo, 64);
  printf("memo %s\n", memo);
  return 0;
}
```
name이 memo보다 위에 위치하므로 name에 9byte를 입력하면 카나리 값에 널 바이트가 있는 것이 아닌 한 카나리 값을 얻을 수 있음 <br>
memo 값을 입력 받을 때 name까지 덮을 16byte + Canary 8byte를 입력




