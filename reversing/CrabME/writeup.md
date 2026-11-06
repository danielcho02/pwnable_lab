# ✏️ CrabME

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 Rust로 빌드된 ELF 하나다. 심볼이 살아 있어서 분석할 지점을 바로 찾을 수 있다.

```text
chal: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

```text
$ nm -C chal | grep ' chal::'
0000000000008030 t chal::flagchecker
0000000000007cc0 t chal::hex_to_u32_vec
0000000000007c10 t chal::fail
0000000000007dc0 t chal::main
0000000000007c50 t chal::success
```

실행하면 한 줄을 받아 맞는지만 알려준다.

```text
$ echo 41414141 | ./chal
🦀 input: Wrong!
```

### main (0x7DC0)

흐름은 단순하다.

```rust
let line = stdin().read_line();
let s = line.trim_matches(..);              // 개행 제거
let v = hex_to_u32_vec(s);                  // Vec<u32>
if flagchecker(&v) { success(s) } else { fail() }
```

`success`(0x7C50)는 **입력 문자열을 그대로** 포맷에 끼워 출력한다.

```text
"Correct! flag is DH{" + input + "}"
```

즉 플래그가 바이너리 안에 문자열로 들어 있는 게 아니라, **검사를 통과하는 입력 자체가 플래그**다.

### hex_to_u32_vec (0x7CC0) — 입력 형식

```asm
7ced:  cmp    $0x40,%rax           ; 길이 64 에서 루프 종료
7cf3:  movzbl (%rsi,%rax,1),%ecx
7cd3:  lea    -0x30(%rcx),%edx     ; c - '0' < 10 ?
7cd6:  cmp    $0xa,%edx
7cd9:  setb   %dl
7cdc:  add    $0xffffff9f,%ecx     ; c - 'a' < 6 ?
7cdf:  cmp    $0x6,%ecx
7ce2:  setb   %cl
7ce5:  or     %dl,%cl
7ce7:  je     7dae                 ; 둘 다 아니면 에러 리턴
```

- 입력은 정확히 **64글자**
- 각 글자는 `[0-9a-f]` (대문자는 거부)
- 2글자씩 묶어 u32 32개로 변환 (`try_process`로 `Vec<u32>` 생성)

UTF-8 멀티바이트 디코딩 분기(`0xdf`, `0xf0`, `0x110000` 비교)가 끼어 있어 디스어셈블리가 길어 보이지만, 유효 입력 범위에서는 ASCII 경로만 타므로 무시해도 된다.

### flagchecker (0x8030) — 바이트별 변환

```asm
8038:  cmpq   $0x20,0x10(%rdi)     ; vec.len() == 32 이어야 한다
...
8066:  movaps 0x40f93(%rip),%xmm0  ; 0x49000 의 128바이트 테이블을
806d:  movups %xmm0,(%rax)         ; 힙으로 복사 (u32 x 32)
...
80e1:  mov    (%r14,%r15,4),%edx   ; edx = input[i]
```

루프 본문이 변환의 전부다.

```asm
80e5:  lea    0x0(,%rdx,8),%esi
80ee:  and    $0x8,%edi            ; bit0 -> bit3
80f4:  shr    $1,%r8d
80f7:  and    $0x1,%r8d            ; bit1 -> bit0
8100:  and    $0x4,%edi
8103:  lea    (%r8,%rdi,4),%edi    ; bit2 -> bit4
810a:  shr    $0x2,%r8d
8111:  and    $0x2,%r9d            ; bit3 -> bit1
8118:  and    $0x80,%esi           ; bit4 -> bit7
8123:  and    $0x20,%edi
8126:  lea    (%rsi,%rdi,2),%esi   ; bit5 -> bit6
8129:  shr    $0x4,%edx
812c:  and    $0x4,%edx            ; bit6 -> bit2
8131:  and    $0x20,%r8d           ; bit7 -> bit5
8138:  xor    $0x63,%r8d           ; ^= 0x63
813c:  add    $0x22,%r8d           ; += 0x22
8140:  movzbl %r8b,%edx            ; u8 로 절단
8144:  cmp    %edx,(%rax,%r15,4)   ; 테이블과 비교
8148:  je     80d0                 ; 틀리면 루프 탈출 -> false
```

정리하면 바이트 하나당 다음 세 단계다.

```c
// 1) 비트 퍼뮤테이션: 입력 bit i -> 출력 bit PERM[i]
//    PERM = {3, 0, 4, 1, 7, 6, 2, 5}
// 2) ^= 0x63
// 3) += 0x22  (u8 wrap)
```

### 기대값 테이블 (0x49000)

u32 32개, 전부 하위 1바이트만 쓴다.

```text
 49000 ae000000 6d000000 9b000000 92000000
 49010 13000000 2b000000 c6000000 c9000000
 49020 e5000000 fa000000 96000000 0b000000
 49030 64000000 31000000 b8000000 08000000
 49040 c8000000 48000000 d2000000 30000000
 49050 60000000 04000000 fa000000 7b000000
 49060 88000000 b0000000 2f000000 7c000000
 49070 b3000000 b3000000 58000000 61000000
```

### 취약점

검사가 **바이트 단위로 완전히 독립적**이다. 바이트 사이의 체이닝(이전 결과를 다음 라운드에 섞기)이 전혀 없고, 변환도 비트 퍼뮤테이션 + XOR + 덧셈이라 전단사다. 따라서 256개짜리 역테이블 하나만 만들면 32바이트를 한 번에 복원할 수 있다. 전체 탐색 공간은 `16^64`지만 실제로는 `256 × 32`번 계산이면 끝난다.

## 🗡️ Exploit / Solver Strategy

1. `forward(v)` = 퍼뮤테이션 → `^0x63` → `+0x22` 를 그대로 구현한다.
2. `v = 0..255` 전부 넣어 `{forward(v): v}` 역테이블을 만든다 (단사임을 assert로 확인).
3. 테이블 32개를 역테이블에 넣어 원래 바이트를 복원한다.
4. 복원한 32바이트를 소문자 hex 64글자로 이어 붙이면 그게 입력이자 플래그 본문이다.

복원된 바이트는 ASCII가 아니라 그냥 랜덤 바이트다. `success`가 입력 문자열을 그대로 출력하기 때문에 hex 문자열 자체가 플래그 내용이 된다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
import subprocess
import sys

# flagchecker 0x80E1~0x8135 의 비트 이동: 입력 bit i -> 출력 bit PERM[i]
PERM = [3, 0, 4, 1, 7, 6, 2, 5]

# .rodata 0x49000 (u32 x 32)
EXPECTED = [
    0xAE, 0x6D, 0x9B, 0x92, 0x13, 0x2B, 0xC6, 0xC9,
    0xE5, 0xFA, 0x96, 0x0B, 0x64, 0x31, 0xB8, 0x08,
    0xC8, 0x48, 0xD2, 0x30, 0x60, 0x04, 0xFA, 0x7B,
    0x88, 0xB0, 0x2F, 0x7C, 0xB3, 0xB3, 0x58, 0x61,
]


def forward(v):
    """flagchecker 가 입력 바이트 한 개에 적용하는 변환."""
    out = 0
    for i in range(8):
        if v >> i & 1:
            out |= 1 << PERM[i]
    out ^= 0x63
    return (out + 0x22) & 0xFF


table = {forward(v): v for v in range(256)}
assert len(table) == 256, 'not injective'

answer = ''.join('%02x' % table[e] for e in EXPECTED)
print('[*] input :', answer)
print('[*] flag  : DH{%s}' % answer)

if len(sys.argv) > 1:
    out = subprocess.run([sys.argv[1]], input=(answer + '\n').encode(),
                         capture_output=True).stdout.decode()
    print('[*] verify:', out.strip())
```

## 🏳️ cat flag

```text
$ python3 crabme.py ./chal
[*] input : <REDACTED>
[*] flag  : DH{<FLAG_REDACTED>}
[*] verify: 🦀 input: Correct! flag is DH{<FLAG_REDACTED>}
```

플래그 본문이 hex 64글자라 입력과 플래그가 동일하다. 원격 서버 없이 로컬에서 바로 확인된다.
