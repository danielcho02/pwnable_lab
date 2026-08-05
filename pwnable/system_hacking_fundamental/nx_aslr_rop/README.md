# 🧠 Concept: NX & ASLR <br>

## 📌 Background <br>
Stack Buffer Overflow 취약점 발생 <br>
1. 반환 주소 조작 가능 <br>
2. 버퍼의 주소 값을 쉽게 알 수 있음 - 임의 버퍼의 주소를 알기 어렵게 만들 필요 <br>
3. 해당 버퍼가 실행 가능한 메모리임 - 불필요하게 메모리에 실행 권한 주지 않도록 보호 <br>

   **ASLR(Address Space Layout Radomization) & NX(No-eXecute) 보호 기법 개발**  <br>


### 📄 NX(No-eXecute) <br>
실행에 사용되는 메모리 영역과 쓰기에 사용되는 메모리 영역을 분리하는 보호기법 <br>
r2s.c 를 gcc -o r2s r2s.c로 compile <br>
이전에 작성한 exploit 코드를 실행 <br>

 ``` bash
$ python3 r2s.py
[+] Starting local process './r2s': pid 3797175
[+] Address of buf: 0x7ffe4844a7a0
[+] buf <=> sfp: 0x60
[+] buf <=> canary: 0x58
[+] Canary: 0xcf1fcf14f3720b00
[*] Switching to interactive mode
 [*] Got EOF while reading in interactive
$
[*] Process './r2s' stopped with exit code -11 (SIGSEGV) (pid 3797175)
[*] Got EOF while sending in interactive
$
```
Segmentation fault(SIGSEGV) 발생 - 실행 권한이 없어 셸코드가 실행되지 못하고 종료 <br>


### 📄 ASLR(Address Space Layout Randomization) <br>
바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당하는 보호기법 <br>

```bash
$ ./r2s
Address of the buf: 0x7ffe8624a160
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C
$ ./r2s
Address of the buf: 0x7ffd7dad3630
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C
$ ./r2s
...
```
buf의 주소가 실행마다 변경: 리눅스 시스템 커널에서 지원 <br>
``` bash
$ cat /proc/sys/kernel/randomize_va_space
2
```

해당 명령어로 적용되는 메모리 영역 확인 가능 <br>
```
0 : No ASLR <br>
1: Conservative Randomization (스택, 라이브러리, vdso, etc.) <br>
2: Conservative Randomization + brk <br>
```
