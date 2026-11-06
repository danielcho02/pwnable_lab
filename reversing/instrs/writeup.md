# ✏️ instrs

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 stripped PIE 바이너리 `prob`와 Dockerfile이다. Dockerfile을 보면 `socat`으로 포트 31337에 그대로 물려 둔 원격 문제고, flag는 작업 디렉터리의 `./flag`에서 읽는다.

```dockerfile
CMD socat -T 25 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/prob
```

실행하면 프로그램을 입력받는다.

```text
$ echo "" | ./prob
Enter Your Program
No Hack!
```

### main (0x151D)

```c
init();                             // setvbuf x3, signal(SIGALRM, handler), alarm(5)
memset(prog, 0, 8);                 // prog @ 0x4050
memset(mem, 0, 8);                  // mem  @ 0x4060
dp = 0;                             // dp   @ 0x4070
pc = dp;                            // pc   @ 0x406c
puts("Enter Your Program");
read(0, prog, 8);                   // 프로그램은 딱 8바이트
prog[8] = 0;
result = vm();
printf("Result: %d\n", result);
if ( result > 99999 )               // 0x1869F
{
  fp = fopen("./flag", "r");
  getline(&line, &n, fp);
  printf("Good, get the flag: %s", line);
}
```

`init`(0x12EA)에서 `alarm(5)`를 걸고, `SIGALRM` 핸들러(0x12C9)는 `"Machine Time Ended"`를 찍고 `exit(-1)`한다. 즉 **5초 안에** 끝나야 한다.

### vm (0x136D)

```c
int vm(void) {
    int steps = 0;
    while (1) {
        int halt = 0;
        steps++;
        switch (prog[pc]) { ... }        // 아래 ISA
        if (!halt) { pc++; if (pc > 7) pc = 7; }
        else return steps;               // 0x1518: mov -0x8(%rbp), %eax
    }
}
```

**리턴값이 "실행한 명령어 개수"다.** 즉 8바이트짜리 프로그램으로 10만 스텝 이상 돌린 뒤 정상 종료시키는 게 목표다.

디스패치는 두 단계다.

```asm
13a1:  cmp    $0x72,%eax        ; > 'r' 이면 invalid
13a4:  jg     14c1
13aa:  cmp    $0x61,%eax        ; 'a' 이상이면 점프 테이블
13ad:  jge    13be
13af:  cmp    $0x2b,%eax        ; '+'
13b2:  je     13ed
13b4:  cmp    $0x2d,%eax        ; '-'
13b7:  je     141a
13b9:  jmp    14c1              ; 나머지 전부 invalid
...
13be:  sub    $0x61,%eax
13c1:  cmp    $0x11,%eax        ; 'a'..'r' (18개) 범위 밖이면 invalid
13c4:  ja     14c1
13d4:  lea    0xc45(%rip),%rax  ; 0x2020 점프 테이블
13ea:  notrack jmp *%rax
```

점프 테이블(0x2020, `int32` 상대 오프셋 18개)을 풀면 실제로 구현된 건 5개뿐이다.

```text
a -> 0x1447     e -> 0x14B8     l -> 0x146D     n -> 0x14DA     r -> 0x1492
b,c,d,f..k,m,o,p,q -> 0x14C1 ("No Hack!" + exit(-1))
```

### ISA

| 명령 | 주소 | 동작 |
|---|---|---|
| `+` | 0x13ED | `mem[dp]++` (u8) |
| `-` | 0x141A | `mem[dp]--` (u8) |
| `l` | 0x146D | `dp--`, 0 미만이면 0으로 clamp |
| `r` | 0x1492 | `dp++`, 7 초과면 7로 clamp |
| `n` | 0x14DA | nop |
| `a` | 0x1447 | `mem[dp] != 0` 이면 **`pc = 0`** (증가 없이), 0이면 다음 명령으로 |
| `e` | 0x14B8 | halt → 스텝 수 리턴 |

`pc`도 7에서 clamp된다(0x14F9). 그래서 halt 없이 끝까지 가면 `prog[7]`을 무한 반복하다 alarm에 걸린다.

```asm
1447:  ...                      ; a: mem[dp] 로드
145a:  test   %al,%al
145c:  je     14dd              ; 0 이면 통과 (pc++)
145e:  movl   $0x0,0x2c04(%rip) ; pc = 0
1468:  jmp    1512              ; pc++ 를 건너뛰고 루프 처음으로
```

### 취약점

점프 명령이 `a` 하나뿐이고 그 목적지가 **항상 프로그램 맨 앞(pc = 0)** 이다. 겉보기엔 단순 `while` 하나만 가능해 보이지만,

- `a`는 셀이 0일 때 **아래로 흘러간다**
- 뒤쪽에 `a`를 하나 더 두고 **다른 셀**을 보게 하면, 그 두 번째 `a`가 바깥 루프가 된다
- 바깥 루프가 pc = 0으로 돌아갈 때 `dp`는 그대로 남아 있으므로, 맨 앞에서 `l`로 `dp`를 되돌려 주면 안쪽 루프가 다시 첫 셀을 보게 된다

이걸로 8바이트 안에 2중 루프가 만들어진다. 셀이 `u8`이라 `0 - 1 = 255`가 되어 카운터 초기화도 `-` 한 번으로 끝난다.

## 🗡️ Exploit / Solver Strategy

```text
pos  op   의미
 0   l    dp = 0            <- 바깥 루프에서 돌아왔을 때 dp 복구
 1   -    mem[0]--          0 -> 255 (wrap) 이므로 0 이 되려면 256 번
 2   a    mem[0] != 0 -> goto 0      안쪽 루프: 3명령 x 256회 = 768
 3   r    dp = 1
 4   -    mem[1]--
 5   a    mem[1] != 0 -> goto 0      바깥 루프: 771명령 x 256회
 6   e    halt
```

- 안쪽 루프 한 바퀴 = `l`, `-`, `a` 3스텝, `mem[0]`이 0이 될 때까지 256회 → 768스텝
- 그 뒤 `r`, `-`, `a` 3스텝 → 바깥 루프 한 바퀴 771스텝
- `mem[1]`도 256회 → `256 * 771 + 1(e) = 197377`

`197377 > 99999`로 조건을 넘고, 20만 스텝은 네이티브 속도라 `alarm(5)`에 걸리지 않는다. 입력은 7바이트지만 `read(0, prog, 8)` 안에 들어가고, `e`에서 멈추므로 8번째 바이트(개행)는 실행되지 않는다.

```text
payload: l-ar-ae
```

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
from pwn import *

PROGRAM = b'l-ar-ae'


def simulate(prog):
    """바이너리 없이 스텝 수를 미리 계산해 보는 참고용 시뮬레이터."""
    prog = prog.ljust(8, b'\x00')
    mem = [0] * 8
    pc = dp = steps = 0
    while True:
        op = prog[pc]
        steps += 1
        halt = False
        if op == ord('+'):
            mem[dp] = (mem[dp] + 1) & 0xFF
        elif op == ord('-'):
            mem[dp] = (mem[dp] - 1) & 0xFF
        elif op == ord('l'):
            dp = max(dp - 1, 0)
        elif op == ord('r'):
            dp = min(dp + 1, 7)
        elif op == ord('n'):
            pass
        elif op == ord('a'):
            if mem[dp] != 0:
                pc = 0
                continue
        elif op == ord('e'):
            halt = True
        else:
            raise ValueError('No Hack! (invalid op %r)' % chr(op))
        if halt:
            return steps
        pc = min(pc + 1, 7)


log.info('simulated steps: %d', simulate(PROGRAM))

p = remote("host3.dreamhack.games", 14977)
# p = process("./prob")

p.recvuntil(b"Enter Your Program\n")
p.send(PROGRAM)

print(p.recvall(timeout=10).decode(errors="replace").strip())
```

## 🏳️ cat flag

시뮬레이터가 계산한 스텝 수와 바이너리가 출력한 `Result`가 정확히 일치한다.

```text
$ python instrs.py
[*] simulated steps: 197377
[+] Opening connection to host3.dreamhack.games on port 14977: Done
[+] Receiving all data: Done (104B)
Result: 197377
Good, get the flag: DH{<FLAG_REDACTED>}
```

로컬에서 먼저 돌려 볼 때는 `./flag`를 직접 만들어 두고 `p = process("./prob")` 쪽 주석을 바꿔 끼우면 된다.
