# 🧠 Concept: Calling Convention

## 📌 Definition  
함수의 호출 및 반환에 대한 약속<br>
Caller는 Return Address와 Stack Frame을 저장, Callee가 요구하는 인자 전달<br>
함수 실행 종료 시 return값 전달<br>

### 💻 x86 Architecture  
컴파일러는 CPU Architecture에 맞는 호출 규약을 선택<br>
x86(32bit) 레지스터의 수가 적으므로 Stack으로 인자 전달<br>

```c
void callee(int a1, int a2, int a3){
}

void caller(){
   callee(1, 2, 3);
}
```

### cdecl
- Linux gcc가 x86 바이너리를 컴파일할 때 일반적으로 사용하는 호출 규약
- Stack으로만 인자 전달, 호출자가 정리
- 마지막 인자부터 거꾸로 push

```asm
; Name: cdecl.s
	.file	"cdecl.c"
	.intel_syntax noprefix
	.text
	.globl	callee
	.type	callee, @function
callee:
	nop
	ret
	.size	callee, .-callee
	.globl	caller
	.type	caller, @function
caller:
	push	3 ; 3을 스택에 저장하여 callee의 인자로 전달합니다.
	push	2 ; 2를 스택에 저장하여 callee의 인자로 전달합니다.
	push	1 ; 1을 스택에 저장하여 callee의 인자로 전달합니다.
	call	callee
	add	esp, 12 ; 호출자가 총 12바이트 만큼 스택을 정리합니다. (push를 3번하였기 때문에 12바이트 만큼 esp가 증가되어 있습니다.)
	nop
	ret
	.size	caller, .-caller
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
```

### stdcall(standard call)
- Winodws API에서 기본적으로 사용되는 함수 호출 규약, cdecl 변형
- 피호출자가 스택 정리

```asm
callee:
    push ebp
    mov ebp, esp
    leave
    retn 12 ; 피호출자가 총 12바이트 만큼 스택을 정리합니다.
caller:
    push ebp
    mov ebp, esp
    push 3 ; 3을 스택에 저장하여 callee의 인자로 전달합니다.
    push 2 ; 2를 스택에 저장하여 callee의 인자로 전달합니다.
    push 1 ; 1을 스택에 저장하여 callee의 인자로 전달합니다.
    call callee
    leave
    ret
```

### fastcall
- 일부 인자를 레지스터로 전달, 속도 향상
- 처음 두 개의 인자를 각각 ecx, edx로 전달 후 나머지 인자는 마지막부터 스택으로 전달

```asm
callee:
    push ebp
    mov ebp, esp
    leave
    retn 4 ; 피호출자가 총 4바이트 만큼 스택을 정리합니다.
caller:
    push ebp
    mov ebp, esp
    mov ecx, 1 ; ecx를 통해 1을 callee의 인자로 전달합니다.
    mov edx, 2 ; edx를 통해 2를 callee의 인자로 전달합니다.
    push 3 ; 3을 스택에 저장하여 callee의 인자로 전달합니다.
    call callee
    leave
    ret
```

### thiscall
- C++ 클래스 멤버 함수를 위한 호출 규약
- mov ecx, this pointer

```c
class C
{
public:
	int c;
	int foo(int a, int b)
	{
		return c + a + b;
	}
};
```

foo 함수를 어셈블리 코드로 변환

```asm
foo:                    ; __thiscall C::foo(int a, int b)
  ...
  mov     eax, [ebp+8] ; eax에 스택에 있는 a의 값 대입합니다.
  add     eax, [ebp+12] ; eax에 스택에 있는 b의 값을 더합니다.
  add     eax, [ecx] ; eax에 this->c의 값을 더합니다.

  leave
  retn    8 ; 피호출자가 총 8바이트 만큼 스택을 정리합니다.
```

ecx가 this pointer를 가리키고 이를 이용해 class의 member 변수에 접근 가능, [ecx + offset]의 형태로 사용

```c
class C
{
public:
	int c;
    int d;
    unsigned long e;
	int foo(int a, int b)
	{
		return c + d + e + a + b;
	}
};
```

```asm
foo:                    ; __thiscall C::foo(int a, int b)
  ...
  mov     eax, [ebp+8]
  add     eax, [ebp+12]
  add     eax, [ecx] ; this->c
  add     eax, [ecx+4] ; this->d
  add     eax, [ecx+8] ; this->e

  leave
  retn    8
```

### 💻 x86-64 Architecture: SYSV

x86-64 레지스터의 수가 많으므로 적은 수의 인자는 레지스터를 사용해 전달, 인자가 너무 많을 때만 Stack 사용  
C언어 컴파일 시 Windows는 MSVC를, Linux는 gcc를 주로 사용  
MSVC는 x64 호출 규약 적용, gcc는 SYSTEM V 호출 규약 적용  

- 6개 인자를 rdi, rsi, rdx, rcx, r8, r9에 순서대로 저장하여 전달, 더 많은 인자 사용시 Stack을 추가로 이용
- Caller에서 인자 전달에 사용된 스택을 정리
- 함수의 반환 값은 rax로 전달

```c
// Name: sysv.c
// Compile: gcc -fno-asynchronous-unwind-tables -masm=intel \ 
//         -fno-omit-frame-pointer -o sysv sysv.c -fno-pic -O0

#define ull unsigned long long

ull callee(ull a1, int a2, int a3, int a4, int a5, int a6, int a7) {
  ull ret = a1 + a2 + a3 + a4 + a5 + a6 + a7;
  return ret;
}

void caller() { callee(123456789123456789, 2, 3, 4, 5, 6, 7); }

int main() { caller(); }
```

<br>

1. 인자 전달 <br>
gdb로 sysv를 로드한 후, caller()에 중단점 설정

```asm
$ gdb -q sysv
pwndbg: loaded 139 pwndbg commands and 49 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from sysv...
...
pwndbg> b *caller
Breakpoint 1 at 0x1185
pwndbg> r
Starting program: /home/dreamhack/sysv

Breakpoint 1, 0x0000555555555185 in caller ()
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x555555555185 <caller>       endbr64
   0x555555555189 <caller+4>     push   rbp
   0x55555555518a <caller+5>     mov    rbp, rsp
   0x55555555518d <caller+8>     push   7
   0x55555555518f <caller+10>    mov    r9d, 6
   0x555555555195 <caller+16>    mov    r8d, 5
   0x55555555519b <caller+22>    mov    ecx, 4
   0x5555555551a0 <caller+27>    mov    edx, 3
   0x5555555551a5 <caller+32>    mov    esi, 2
   0x5555555551aa <caller+37>    movabs rax, 0x1b69b4bacd05f15
   0x5555555551b4 <caller+47>    mov    rdi, rax
   0x5555555551b7 <caller+50>    call   0x555555555129 <callee>
   0x5555555551bc <caller+55>    add    rsp,0x8
...
```

```asm
pwndbg> disass caller
...
   0x00005555555551b7 <+50>:  call   0x555555555129 <callee>
...
pwndbg> b *caller+50
Breakpoint 2 at 0x5555555551b7
```

continue, callee() 호출 직전에 중단

```asm
pwndbg> c
Continuing.

Breakpoint 2, 0x00005555555551b7 in caller ()
...
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0x1b69b4bacd05f15
 RBX  0x0
*RCX  0x4
*RDX  0x3
*RDI  0x1b69b4bacd05f15
*RSI  0x2
*R8   0x5
*R9   0x6
 R10  0x7ffff7fc3908 ◂— 0xd00120000000e
 R11  0x7ffff7fde680 (_dl_audit_preinit) ◂— endbr64
...

pwndbg> x/4gx $rsp
0x7fffffffe2f8: 0x0000000000000007  0x00007fffffffe310
0x7fffffffe308: 0x00005555555551d5  0x0000000000000001
```

인자들이 순서대로 rdi, rsi, rdx, rcx, r8, r9, [rsp]에 설정되어 있음 <br><br>

2. 변환 주소 저장<br>

```asm
pwndbg> si
0x00005555555545fa in callee ()
...
pwndbg> x/4gx $rsp
0x7fffffffdf70:	0x0000555555554682	0x0000000000000007
0x7fffffffdf80:	0x00007fffffffdf90	0x0000555555554697
pwndbg> x/10i 0x0000555555554682 - 5
   0x55555555467d <caller+43>:	call   0x5555555545fa <callee>
   0x555555554682 <caller+48>:	add    rsp,0x8
```

0x555555554862 callee() 호출 다음 명령어의 주소이므로 원래의 실행 흐름으로 돌아갈 수 있음 <br>

3. 스택 프레임 저장<br>
x/9i rip 명령어 이용  
push rbp를 통해 caller() 이전 함수 위치 기억  
rbp가 Stack Frame의 가장 낮은 주소를 가리키는 Pointer(SFP)  
callee()에서 반환될 때, caller()의 스택프레임으로 돌아갈 수 있음  
함수는 잠깐 실행되는 블록이므로 반드시 원래 위치로 돌아가야함<br>

```asm
pwndbg> x/9i $rip
=> 0x555555555129 <callee>:	endbr64
   0x55555555512d <callee+4>:	push   rbp
   0x55555555512e <callee+5>:	mov    rbp,rsp
   0x555555555131 <callee+8>:	mov    QWORD PTR [rbp-0x18],rdi
   0x555555555135 <callee+12>:	mov    DWORD PTR [rbp-0x1c],esi
   0x555555555138 <callee+15>:	mov    DWORD PTR [rbp-0x20],edx
   0x55555555513b <callee+18>:	mov    DWORD PTR [rbp-0x24],ecx
   0x55555555513e <callee+21>:	mov    DWORD PTR [rbp-0x28],r8d
   0x555555555142 <callee+25>:	mov    DWORD PTR [rbp-0x2c],r9d
pwndbg> si
pwndbg> si
0x000055555555512e in callee ()
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x555555555129 <callee>       endbr64
   0x55555555512d <callee+4>     push   rbp
 ► 0x55555555512e <callee+5>     mov    rbp, rsp
   0x555555555131 <callee+8>     mov    qword ptr [rbp - 0x18], rdi
...
pwndbg> x/4gx $rsp
0x7fffffffe2e8: 0x00007fffffffe300  0x00005555555551bc
0x7fffffffe2f8: 0x0000000000000007  0x00007fffffffe310
pwndbg> print $rbp
$1 = (void *) 0x7fffffffe300
```

si로 push rbp를 실행, 0x00007fffffffe300이 저장 <br>

4. 스택 프레임 할당<br>
mov rbp, rsp로 rbp와 rsp가 같은 주소를 가리키게 함 -> callee가 자기 스택에서 변수와 인자 접근을 쉽게 하기 위함  
callee()는 지역변수를 사용하지 않음 ret은 레지스터로 처리가 가능하므로 stack frame을 만들지 않음 <br>

```asm
pwndbg> x/5i $rip
=> 0x55555555512e <callee+5>: mov    rbp,rsp
   0x555555555131 <callee+8>: mov    QWORD PTR [rbp-0x18],rdi
   0x555555555135 <callee+12>:  mov    DWORD PTR [rbp-0x1c],esi
   0x555555555138 <callee+15>:  mov    DWORD PTR [rbp-0x20],edx
   0x55555555513b <callee+18>:  mov    DWORD PTR [rbp-0x24],ecx

pwndbg> print $rbp
$2 = (void *) 0x7fffffffe300
pwndbg> print $rsp
$3 = (void *) 0x7fffffffe2e8

pwndbg> si

pwndbg> print $rbp
$4 = (void *) 0x7fffffffe2e8
pwndbg> print $rsp
$5 = (void *) 0x7fffffffe2e8
```

<br>

5. 반환값 전달 <br>
반환값을 rax에 mov, 출력시 7개 인자의 합인 123456789123456816 <br>

```asm
pwndbg> b *callee+79
Breakpoint 3 at 0x555555555178
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x555555555178 <callee+79>    add    rax, rdx
   0x55555555517b <callee+82>    mov    qword ptr [rbp - 8], rax
   0x55555555517f <callee+86>    mov    rax, qword ptr [rbp - 8]
   0x555555555183 <callee+90>    pop    rbp
   0x555555555184 <callee+91>    ret

pwndbg> b *callee+91
Breakpoint 4 at 0x555555555184
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x555555555178 <callee+79>    add    rax, rdx
   0x55555555517b <callee+82>    mov    qword ptr [rbp - 8], rax
   0x55555555517f <callee+86>    mov    rax, qword ptr [rbp - 8]
   0x555555555183 <callee+90>    pop    rbp
 ► 0x555555555184 <callee+91>    ret                                  <0x5555555551bc; caller+55>
    ↓
...

pwndbg> print $rax
$1 = 123456789123456816
```

<br>

6. 반환 <br>
ret로 호출자로 복귀 <br>

```asm
pwndbg> d
pwndbg> b *callee+90
Breakpoint 1 at 0x1183
pwndbg> r
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x555555555183 <callee+90>                     pop    rbp
   0x555555555184 <callee+91>                     ret
    ↓
...

pwndbg> si
pwndbg> si
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x555555555183 <callee+90>                     pop    rbp
   0x555555555184 <callee+91>                     ret
    ↓
 ► 0x5555555551bc <caller+55>                     add    rsp, 8
   0x5555555551c0 <caller+59>                     nop
   0x5555555551c1 <caller+60>                     leave
   0x5555555551c2 <caller+61>                     ret
    ↓
...
pwndbg> print $rbp
$1 = (void *) 0x7fffffffe300
pwndbg> print $rip
$2 = (void (*)()) 0x5555555551bc <caller+55>
```

## 📚 Summary 

- x86 <br>

| 호출 규약    | 사용 컴파일러   | 인자 전달 방식             | 스택 정리  | 적용        |
| -------- | --------- | -------------------- | ------ | --------- |
| cdecl    | GCC, MSVC | Stack                | Caller | 일반 함수     |
| stdcall  | MSVC      | Stack                | Callee | WinAPI    |
| fastcall | MSVC      | ECX, EDX             | Callee | 최적화된 함수   |
| thiscall | MSVC      | ECX(this), Stack(인자) | Callee | 클래스 멤버 함수 |

- x86-64 <br>

| 호출 규약        | 사용 컴파일러 | 인자 전달 방식                           | 스택 정리  | 적용                     |
| ------------ | ------- | ---------------------------------- | ------ | ---------------------- |
| System V ABI | GCC     | RDI, RSI, RDX, RCX, R8, R9, XMM0-7 | Caller | 일반 함수                  |
| MS ABI       | MSVC    | RCX, RDX, R8, R9                   | Caller | 일반 함수, Windows Syscall |





