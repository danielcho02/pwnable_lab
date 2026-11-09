# ✏️ Honest

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 심볼이 살아 있는 PIE 바이너리 하나다.

```text
main: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

```text
$ ./main
How to use: ./main <flag>
$ ./main AAAA
Wrong!
```

심볼을 보면 `main`, `calculate`, 그리고 `verify_func_0` ~ `verify_func_62` 63개가 있다.

```text
$ nm main | grep -c verify_func
63
```

### main (0x126F) — 정직해 보이는 쪽

```c
int main(int argc, char **argv, char **envp) {
    if (argc != 2) { puts("How to use: ./main <flag>"); exit(0); }
    if (strlen(argv[1]) != 0x40) correct = 0;          // 길이 64

    c = argv[1][counter++];                            // counter @ 0x6018
    if (calculate(c) != 0xBD) correct = 0;             // correct @ 0x6010 (초기값 1)

    if (counter > 0x3F) return 0;

    verify_func_2(argc, argv, envp);                   // 다음 고리

    if (correct) printf("Correct! Flag is DH{%s}", argv[1]);
    else         puts("Wrong!");
    return 0;
}
```

`verify_func_*` 63개도 전부 같은 모양이고, 각자 **자기만의 비교 상수**와 **자기만의 다음 함수**를 가진다. 63개 함수 모두 `cmp $0x..,%al`이 정확히 하나, 체인 호출이 정확히 하나씩이다.

```c
int verify_func_N(int argc, char **argv, char **envp) {
    if (argc != 2) { puts("How to use: ./main <flag>"); exit(0); }
    c = argv[1][counter++];
    if (calculate(c) != <상수>) correct = 0;
    if (counter > 0x3F) return 0;
    return <다음 함수>(argc, argv, envp);
}
```

전역 `counter`를 공유하면서 하나씩 소비하므로 **체인 실행 순서가 곧 플래그 인덱스**다. 64번째에서 `counter > 0x3F`가 되어 체인이 멈추고, 호출이 되돌아 나오면서 결과가 출력된다.

### 함정: `main`은 진입점이 아니다

`main`에서 체인을 따라가면 `main → verify_func_2 → verify_func_1 → verify_func_9 → ...`가 되고, 64개 노드를 한 번씩 방문하는 깔끔한 경로가 나온다. 그런데 이 순서로 복원한 값은 거부당한다.

`_start`를 보면 이유가 나온다.

```asm
00000000000010c0 <_start>:
    10d8:  lea    0x12f1(%rip),%rdi        # 23d0 <verify_func_28>
    10df:  call   *0x4ef3(%rip)            # __libc_start_main@GLIBC_2.34
```

`__libc_start_main`에 넘기는 첫 인자가 `main`이 아니라 **`verify_func_28`** 이다. 즉 프로그램의 실제 시작점은 `verify_func_28`이고, `main`은 체인의 한 고리일 뿐이다. gdb로 함수 진입 순서를 찍어 보면 그대로 확인된다.

```text
verify_func_28 verify_func_47 verify_func_61 verify_func_59 ... verify_func_0 main verify_func_2 ...
```

`main`은 56번째, 즉 **index 55**에서 실행된다. 체인은 64개 노드를 한 바퀴 도는 사이클이라 시작점만 틀려도 플래그가 그만큼 회전(rotate)된 값이 나온다. 그래서 틀린 답도 "그럴듯한 64자 hex"처럼 보인다. 문제 이름 그대로 `main`이 정직하지 않다.

또한 `verify_func_*`가 `(int, char**, char**)` 시그니처를 갖는 이유도 이것이다. 체인 전체가 libc 입장에서 `main`의 자리에서 돌기 때문에 `argc`/`argv`를 그대로 물려받는다.

### calculate (0x11A9)

바이트 하나를 받아 바이트 하나를 돌려주는 변환이다.

```asm
11bd:  xorb   $0x3c,-0x6(%rbp)   ; x ^= 0x3c
11c5:  lea    0x0(,%rax,4),%edx  ; (x << 2) | (x >> 6)      rol 2
11de:  shl    $0x2,%eax
11e1:  add    %edx,%eax          ; x * 5
11e3:  add    $0x7d,%eax         ; + 0x7d
11ed:  shr    $0x3,%al           ; (x >> 3) | (x << 5)      ror 3
11fb:  xor    $0xffffffb2,%eax   ; ^= 0xb2
1205:  shl    $0x4,%eax          ; (x << 4) | (x >> 4)      니블 스왑
121c:  add    %eax,%eax
121e:  add    %edx,%eax          ; x * 3
1220:  sub    $0x2f,%eax         ; - 0x2f
122a:  lea    (%rax,%rax,1),%edx ; (x << 1) | (x >> 7)      rol 1
1236:  xor    $0xffffffd4,%eax   ; ^= 0xd4
1249:  ...                       ; 8비트 비트 리버스
```

`mov %al,-0x6(%rbp)`로 매 단계 u8로 잘린다. 회전, XOR, 홀수 곱(5, 3), 덧셈, 비트 리버스뿐이라 전부 가역이고, 실제로 0~255 전체가 일대일 대응한다.

gdb로 교차 검증하면 모델이 맞는다.

```text
$ gdb -batch -ex 'break calculate' -ex 'run AAAA...' -ex finish ./main
edi=65        # 'A'
ret_al=0x9a   # python 모델도 calculate(0x41) == 0x9a
```

### 취약점

- 바이트 간 체이닝이 없다. 각 위치가 자기 상수와만 비교된다.
- `calculate`가 전단사라 256개 역테이블로 바로 뒤집힌다.
- 비교 상수와 다음 함수 포인터가 전부 정적으로 박혀 있어, 디스어셈블리만 긁어도 순서와 기대값을 다 뽑을 수 있다.

유일한 장애물은 체인의 **시작점**을 `main`이 아니라 `_start`에서 찾아야 한다는 것이다.

## 🗡️ Exploit / Solver Strategy

1. `objdump -d`로 `main`과 `verify_func_*` 64개에서 `cmp $0x..,%al` 상수와 체인 호출 대상을 뽑는다.
2. `_start`의 `__libc_start_main` 첫 인자에서 진입점(`verify_func_28`)을 확인한다.
3. 진입점부터 64칸 따라가며 상수 배열을 순서대로 모은다 (64개 전부 유일한지 assert).
4. `calculate`를 구현해 `{calculate(v): v}` 역테이블을 만든다 (단사 확인).
5. 상수를 역테이블에 넣어 64바이트를 복원한다. 그게 그대로 플래그 본문이다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
import re
import subprocess
import sys

BIN = './main'
ENTRY = 'verify_func_28'  # _start 가 __libc_start_main 에 넘기는 함수


def calculate(c):
    """calculate (0x11A9) 재현. 전단사라 역테이블을 만들 수 있다."""
    x = c ^ 0x3C
    x = ((x << 2) | (x >> 6)) & 0xFF        # rol 2
    x = (x * 5 + 0x7D) & 0xFF
    x = ((x >> 3) | (x << 5)) & 0xFF        # ror 3
    x ^= 0xB2
    x = ((x << 4) | (x >> 4)) & 0xFF        # 니블 스왑
    x = (x * 3 - 0x2F) & 0xFF
    x = ((x << 1) | (x >> 7)) & 0xFF        # rol 1
    x ^= 0xD4
    r = 0                                   # 8비트 비트 리버스
    for _ in range(8):
        r = ((r << 1) | (x & 1)) & 0xFF
        x >>= 1
    return r


def parse(path):
    """함수별 (기대 상수, 다음 함수) 추출."""
    dis = subprocess.run(['objdump', '-d', '--no-show-raw-insn', path],
                         capture_output=True, text=True).stdout
    funcs, cur = {}, None
    for line in dis.splitlines():
        m = re.match(r'^[0-9a-f]+ <(.+)>:$', line)
        if m:
            cur = m.group(1)
            funcs[cur] = []
        elif cur is not None:
            funcs[cur].append(line)

    out = {}
    for name, body in funcs.items():
        if name != 'main' and not name.startswith('verify_func_'):
            continue
        text = '\n'.join(body)
        cmps = re.findall(r'cmp\s+\$0x([0-9a-f]+),%al', text)
        calls = [c for c in re.findall(r'call\s+[0-9a-f]+ <([^>+]+)>', text)
                 if c == 'main' or c.startswith('verify_func_')]
        assert len(cmps) == 1 and len(calls) == 1, (name, cmps, calls)
        out[name] = (int(cmps[0], 16), calls[0])
    return out


def main():
    funcs = parse(sys.argv[1] if len(sys.argv) > 1 else BIN)

    order, consts, cur = [], [], ENTRY
    for _ in range(64):                     # counter > 0x3f 에서 체인이 멈춘다
        const, nxt = funcs[cur]
        order.append(cur)
        consts.append(const)
        cur = nxt
    assert len(set(order)) == 64, 'chain is not a simple path'

    table = {calculate(c): c for c in range(256)}
    assert len(table) == 256, 'calculate not injective'

    flag = bytes(table[c] for c in consts).decode()
    print('[*] chain :', ' -> '.join(order[:4]), '-> ... ->', order[-1])
    print('[*] main is index', order.index('main'))
    print('[*] flag  : DH{%s}' % flag)

    out = subprocess.run([BIN, flag], capture_output=True, text=True).stdout
    print('[*] verify:', out.strip())
    return flag


if __name__ == '__main__':
    main()
```

## 🏳️ cat flag

```text
$ python3 honest.py
[*] chain : verify_func_28 -> verify_func_47 -> verify_func_61 -> verify_func_59 -> ... -> verify_func_34
[*] main is index 55
[*] flag  : DH{<FLAG_REDACTED>}
[*] verify: Correct! Flag is DH{<FLAG_REDACTED>}
```

처음에 `main`을 시작점으로 잡고 복원했을 때는 같은 64자가 **55칸 회전된 문자열**이 나와 `Wrong!`이었다. 사이클 구조라 결과가 그럴듯해 보여서, `_start`를 확인하기 전까지는 `calculate` 쪽을 잘못 읽은 걸로 착각하기 쉽다.
