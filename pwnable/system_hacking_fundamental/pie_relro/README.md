# 🧠 PIE(Position-Independent Executable)

## 📌 Definition
ASLR(Address Space Layout Randomization) 적용 시 바이너리가 실행될 때마다 stack, heap, shared library 등이 무작위 주소에 매핑
하지만 일반적으로 ASLR이 적용되더라도 실행 파일의 `main()`이나 전역 변수 등이 위치한 주소는 항상 고정된 상태
PIE는 실행 파일이 매핑된 영역에도 적용

```c
// Name: addr.c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf_stack[0x10];                   // 스택 영역의 버퍼
    char *buf_heap = (char *)malloc(0x10);  // 힙 영역의 버퍼

    printf("buf_stack addr: %p\n", buf_stack);
    printf("buf_heap addr: %p\n", buf_heap);
    printf("libc_base addr: %p\n",
        *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 영역 주소

    printf("printf addr: %p\n",
        dlsym(dlopen("libc.so.6", RTLD_LAZY),
        "printf"));  // 라이브러리 영역의 함수 주소
    printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```
ASLR과 PIE가 동시에 적용된 경우 스택, 힙, 라이브러리 영역의 주소 뿐만 아니라 main()의 주소도 매번 다르게 출력

## 📄 PIC(Position-Independent Code)
ELF는 실행파일(Executable)과 공유 오브젝트(Shared Object, SO)로 두 가지 존재    
SO는 기본적으로 재배치 가능: 메모리의 어느 주소에 적재되어도 코드의 의미가 훼손되지 않음    
PIC: 재배치 가능한 코드    
코드가 자기 기준점(rip)을 보고 데이터 위치를 계산하니까, 프로그램이 메모리 어디에 올라가도 정상 동작     

## 📄 PIE
PIE: 무작위 주소에 매핑되도 실행 가능한 파일     
리눅스의 실행 파일 형식은 재배치를 고려하지 않고 설계되었기 때문에 원래 재배치가 가능했던 공유 오브젝트를 실행파일로 사용하기로 함    

```bash
$ readelf -h /bin/ls
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x6ab0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          136224 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```
실제로 리눅스의 기본 실행 파일 중 하나인 /bin/ls의 파일 헤더를 살펴보면, Type이 공유오브젝트
DYN(ET_DYN)임을 확인할 수 있음   

PIE는 재배치가 가능하므로 ASLR이 적용된 시스템에서는 실행파일도 무작위 주소에 적재    
반대로, ASLR이 적용되지 않은 시스템에서는 PIE가 적용되더라도 무작위 주소에 적재 X    

```bash
$ gcc -o pie addr.c -ldl
```

여러번 실행해보면 main()의 주소가 매번 바뀌고 있음을 확인 가능    

```bash
$ gcc -o pie addr.c -ldl
$ ./pie
buf_stack addr: 0x7ffc85ef37e0
buf_heap addr: 0x55617ffcb260
libc_base addr: 0x7f0989d06000
printf addr: 0x7f0989d6af00
main addr: 0x55617f1297ba
$ ./pie
buf_stack addr: 0x7ffe9088b1c0
buf_heap addr: 0x55e0a6116260
libc_base addr: 0x7f9172a7e000
printf addr: 0x7f9172ae2f00
main addr: 0x55e0a564a7ba
$ ./pie
buf_stack addr: 0x7ffec6da1fa0
buf_heap addr: 0x5590e4175260
libc_base addr: 0x7fdea61f2000
printf addr: 0x7fdea6256f00
main addr: 0x5590e1faf7ba
```

## 🗡️ PIE 우회   
1. 코드 베이스 구하기   
   -  ASLR환경에서 PIE가 적용된 바이너리는 실행될 따마다 다른 주소에 적재
   -  코드 영역의 가젯을 사용하거나 데이터 영역에 접근하려면 바이너리가 적재된 주소를 알아야함
   -  libc_base 주소와 같이 코드 영역의 임의 주소를 leak offset을 빼기   

2. Partial Overwirte   
   - 코드 영역의 주소도 하위 12비트 값은 항상 같음
   - 사용하려는 코드 가젯의 주소가 반환 주소와 하위 한 바이트만 다르다면 이 값만 덮어서 원하는 코드 실행 가능
   - 두 바이트 이상 다른 주소로 실행 흐름을 옮기려면 브루트 포싱이 필요, 확률적 공격 성공

# 🧠 RELRO(RELocation Read-Only)

## 📌 Definition
Lazy Binding: 호출될 때 함수의 주소를 구하고 GOT에 값을 채우는 방식
Lazy Binding을 하는 바이너리는 실행 중에 GOT 테이블을 업데이트 할 수 있어야 하므로 GOT가 존재하는 메모리 영역에 쓰기 권한이 부여됨    
-> 취약점    
Partial RELRO: 하나의 RELRO를 부분적으로 적용
Full RELRO: 나머지 가장 넓은 영역에 RELRO를 적용    

## 📄 Partial RELRO   
```c
// Name: relro.c
// Compile: gcc -o prelro relro.c -no-pie -fno-PIE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
  FILE *fp;
  char ch;
  fp = fopen("/proc/self/maps", "r");
  while (1) {
    ch = fgetc(fp);
    if (ch == EOF) break;
    putchar(ch);
  }
  return 0;
}
```
checksec으로 확인 가능    
```bash
$ ./prelro
00400000-00401000 r--p 00000000 08:02 2886150                            /home/dreamhack/prelro
00401000-00402000 r-xp 00001000 08:02 2886150                            /home/dreamhack/prelro
00402000-00403000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00403000-00404000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00404000-00405 000 rw-p 00003000 08:02 2886150                            /home/dreamhack/prelro
0130d000-0132e000 rw-p 00000000 00:00 0                                  [heap]
7f108632c000-7f108632f000 rw-p 00000000 00:00 0
7f108632f000-7f1086357000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086357000-7f10864ec000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f10864ec000-7f1086544000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086544000-7f1086548000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086548000-7f108654a000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f108654a000-7f1086557000 rw-p 00000000 00:00 0
7f1086568000-7f108656a000 rw-p 00000000 00:00 0
7f108656a000-7f108656c000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f108656c000-7f1086596000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1086596000-7f10865a1000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a2000-7f10865a4000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a4000-7f10865a6000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffe55580000-7ffe555a1000 rw-p 00000000 00:00 0                          [stack]
7ffe555de000-7ffe555e2000 r--p 00000000 00:00 0                          [vvar]
7ffe555e2000-7ffe555e4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
0x404000 부터 0x405000까지 주소에는 쓰기 권한이 있음   
```bash
$ objdump -h ./prelro

./prelro:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
...
 19 .init_array   00000008  0000000000403e10  0000000000403e10  00002e10  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 20 .fini_array   00000008  0000000000403e18  0000000000403e18  00002e18  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .dynamic      000001d0  0000000000403e20  0000000000403e20  00002e20  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .got          00000010  0000000000403ff0  0000000000403ff0  00002ff0  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got.plt      00000030  0000000000404000  0000000000404000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000010  0000000000404030  0000000000404030  00003030  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000008  0000000000404040  0000000000404040  00003040  2**0
                  ALLOC
...
```
.got.plt, .data, .bss가 할당되어 있어 쓰기가 가능
.init_array와 .fini_array는 각각 0x403e10, 0x403e18에 할당되어 있음   
쓰기 권한이 없는 0040300-0040400 사이에 존재
cf. VMA: 프로그램이 실행될 때 가상 메모리상에서 사용되는 주소 / LMA: RAM에서 실제 실행/사용되는 위치    

## 📄 Full RELRO
```bash
$ ./frelro
563782c64000-563782c65000 r--p 00000000 08:02 2886178                    /home/dreamhack/frelro
563782c65000-563782c66000 r-xp 00001000 08:02 2886178                    /home/dreamhack/frelro
563782c66000-563782c67000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c67000-563782c68000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c68000-563782c69000 rw-p 00003000 08:02 2886178                    /home/dreamhack/frelro
563784631000-563784652000 rw-p 00000000 00:00 0                          [heap]
7f966f91f000-7f966f922000 rw-p 00000000 00:00 0
7f966f922000-7f966f94a000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966f94a000-7f966fadf000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fadf000-7f966fb37000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb37000-7f966fb3b000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3b000-7f966fb3d000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3d000-7f966fb4a000 rw-p 00000000 00:00 0
7f966fb5b000-7f966fb5d000 rw-p 00000000 00:00 0
7f966fb5d000-7f966fb5f000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb5f000-7f966fb89000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb89000-7f966fb94000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb95000-7f966fb97000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb97000-7f966fb99000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffc1bace000-7ffc1baef000 rw-p 00000000 00:00 0                          [stack]
7ffc1bb22000-7ffc1bb26000 r--p 00000000 00:00 0                          [vvar]
7ffc1bb26000-7ffc1bb28000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
got에 쓰기 권한이 제거되어 있으며 data와 bss에만 쓰기 권한이 있음

## 🗡️ RELRO 기법 우회
Partial RELRO의 경우 .init_array와 .fini_array에 대한 쓰기 권한이 제거되어 두 영역을 덮어쓰는 공격을 수행하기 어려움
.got.plt영역에 쓰기 권한이 존재하므로 GOT overwrite 공격을 활용    
Full RELRO의 경우 hook을 이용
__malloc_hook이 존재하는지 검사하고 이를 호출 libc.so에서 x 가능
malloc을 호출하여 실행흐름을 조작 = Hook Overwirte
```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // read hook
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
```

