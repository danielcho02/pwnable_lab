# ✏️ typing_game_goes_hard

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 stripped PIE 바이너리 하나와 **사전 파일**이다.

```text
chall: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
dictionary.txt: 65536 lines
```

`dictionary.txt`가 같이 배포된다는 게 첫 번째 단서다. 바이너리가 이 파일을 읽어 쓴다는 뜻이고, 사전 줄 수 `65536 = 2^16`은 그 자체로 두 번째 단서다.

실행하면 영단어를 90초 안에 따라 치게 한다. EASY 10개, HARD 10개.

```text
Type the following words within 90 seconds.
----------------------------------------------
-                 EASY MODE                  -
----------------------------------------------
Type this word as soon as possible: lactosuria
> lactosuria
...
----------------------------------------------
-                 HARD MODE                  -
----------------------------------------------
Type this word as soon as possible: [REDACTED]
>
```

### main (sub_18EA)

```c
fd = open("/dev/urandom", O_RDONLY);
read(fd, &buf, 4u);                          // 4바이트를 받아 놓고
sub_147B((unsigned __int16)buf);             // 하위 16비트만 시드로 넘긴다  ← 버그
printf("Type the following words within %d seconds.\n", 90);
time(&timer);
for ( i = 0; i <= 1; ++i )                   // i=0 EASY, i=1 HARD
{
  for ( j = 0; j <= 9; ++j )
  {
    s2 = (char *)&unk_4060 + 64 * (unsigned __int16)sub_15D4();   // 출제 단어
    v1 = i ? "[REDACTED]" : s2;                                   // HARD는 가린다
    printf("Type this word as soon as possible: %s\n", v1);
    printf("> ");
    sub_1833(s1, 64);                                             // fgets + strcspn
    time(&time1);
    if ( difftime(time1, timer) > 90.0 || strcmp(s1, s2) != 0 )
    {
      puts("Wrong or too slow!");
      exit(0);
    }
  }
}
printf("You won! flag is ");
sub_1329();                                  // ./flag 를 읽어서 출력
```

핵심은 **가려지는 건 `printf` 출력뿐이고, `strcmp` 비교 대상은 두 모드 모두 `s2`** 라는 점이다. HARD 모드도 정답은 여전히 사전의 단어 하나다. 한 번 틀리면 `exit(0)`이라 시행착오는 불가능하고, 입력 전에 **계산으로 예측**해야 한다.

### 사전 적재: sub_13DF

```c
stream = fopen("./dictionary.txt", "r");
do
  v0 = v2++;
while ( __isoc99_fscanf(stream, "%s", (char *)&unk_4060 + 64 * v0) != -1 );
```

`unk_4060`을 **64바이트 × 65536칸** 테이블로 쓴다. `sub_15D4()`의 반환값이 16비트이므로 `0 ~ 0xFFFF` 전부가 유효한 칸이고, 사전 줄 수와 정확히 1:1 대응한다. 버려지는 인덱스도, 모자란 줄도 없다.

> 참고 — 테이블은 `0x4060`에서 시작해 `0x4060 + 64*65536 = 0x404060`에서 끝나고, 난수 상태 `word_404060`이 바로 그 자리에 붙어 있다. 사전이 65536줄을 넘으면 상태를 덮어쓰게 되는 배치다.

### 난수 생성기

세 함수가 한 세트로 돌아간다. 16비트 워드 8칸을 쓰는 **Mersenne Twister 축소판**이다.

| 함수 | 역할 |
|------|------|
| `sub_147B` | 초기화 — 시드 1개로 상태 8칸을 채운다 |
| `sub_1507` | twist — 8칸을 소모하면 상태 전체를 갱신한다 |
| `sub_15D4` | 출력 — 상태 1칸을 꺼내 tempering 후 반환한다 |

**sub_147B (초기화)**

```c
word_404060[0] = a1;
for ( i = 1; i <= 7; ++i )
  word_404060[i] = 27655 * (word_404060[i-1] ^ ((unsigned __int16)word_404060[i-1] >> 14)) + i;
dword_4010 = 8;
```

1~7번 칸은 0번 칸에서 줄줄이 유도된다. **새로 들어오는 무작위성이 없다.** 시드가 정해지면 상태 128비트 전체가 정해지고, 이후 나올 모든 단어가 정해진다. 즉 비밀은 시드 하나다.

마지막 줄 `dword_4010 = 8`도 중요하다. 아래 `sub_15D4`의 첫 줄이 `if (dword_4010 > 7)`이므로 **첫 출력 전에 twist가 한 번 돌아간다.**

**sub_1507 (twist)**

```c
for ( i = 0; i <= 7; ++i )
{
  v1 = (unsigned __int16)(word_404060[i] & 0x8000 | word_404060[(i+1) % 8] & 0x7FFF) >> 1;
  if ( (word_404060[(i+1) % 8] & 1) != 0 )
    v1 ^= 0x9908u;
  word_404060[i] = v1 ^ word_404060[(i+4) % 8];
}
dword_4010 = 0;
```

MT19937의 twist를 폭 16비트, 상태 8칸으로 줄인 것. 상수 `0x9908`은 MT19937의 `0x9908B0DF` 상위 16비트다. 상태를 **제자리에서 순차 갱신**하므로 `i=4`의 `[(i+4)%8]`=`[0]`, `i=7`의 `[(i+1)%8]`=`[0]`은 **이미 갱신된 값**을 참조한다.

**sub_15D4 (tempering)**

```c
return (((3*n1 + 2*n0 + 5*n2 + 4*n3) & 0xF) << 8)
     | (16 * ((6*n2 + 7*n1 + 4*n0 + 3*n3) & 0xF))
     | (5*n1 + 3*n0 + 7*n2 + 2*n3) & 0xF
     | ((unsigned __int8)((5*n0 + 6*n1 + 4*n2 + 7*n3) & 0xF) << 12);
```

디컴파일 결과가 험악해 보이지만 구조는 단순하다. 입력 16비트를 **니블(4비트) 4개**로 쪼개

| 조각 | 식 |
|------|-----|
| `n0` | `v3 & 0xF` |
| `n1` | `(v3 >> 4) & 0xF` |
| `n2` | `HIBYTE(v3) & 0xF` = `(v3 >> 8) & 0xF` |
| `n3` | `v3 >> 12` |

각 출력 니블을 `(계수 4개 · 입력 니블 4개) mod 16`으로 만들어 `<<12 / <<8 / <<4 / <<0` 제자리에 끼운다. 즉 **mod 16 위의 4×4 행렬 곱**, 16비트 → 16비트 섞기 함수일 뿐이다.

## 🔑 Exploit / Solver Strategy

갖고 있는 능력을 한 문장으로 적으면 경로가 정해진다.

> **EASY 모드에서 출제 단어 10개가 그대로 출력된다. 즉 난수 출력 10개를 공짜로 관측할 수 있다.**

시드 복원 경로는 두 가지다.

- **(A) 역산** — tempering 행렬의 역행렬을 구해 관측 출력에서 상태를 거꾸로 복원한다. 성립하지만 손이 많이 간다.
- **(B) 전수조사** — 가능한 시드를 다 넣어 보고 EASY 10개와 일치하는 것을 찾는다.

여기서 결정적인 사실이 `(unsigned __int16)` 캐스팅이다. urandom에서 32비트를 받아 놓고 **상위 16비트를 버린다.** 시드 공간이 `2^32`가 아니라 `2^16 = 65536`가지로 줄어들어, 전수조사가 파이썬으로도 1~2초면 끝난다. (B)가 압도적으로 싸다. **행렬 역산은 할 필요가 없고, tempering 식을 정방향으로 그대로 옮기기만 하면 된다.**

최종 경로:

1. EASY 10개를 읽어 그대로 되돌려 보낸다 (관측값 확보).
2. 시드 `0 ~ 0xFFFF`를 돌려 첫 출력이 EASY 1번과 맞는 후보만 추리고, 나머지 9개로 검증한다.
3. 시드가 특정되면 **같은 생성기 객체를 이어서** 10번 더 뽑는다 → HARD 정답.
4. 10개를 전송하면 `./flag`가 출력된다.

### 재구현에서 걸리는 지점 3개

- **16비트 wraparound** — C는 16비트 변수에서 넘친 비트를 조용히 버리지만 파이썬 정수는 안 버린다. 곱셈·덧셈 **후** `& 0xFFFF`를 붙인다.
- **`dword_4010 = 8`** — 첫 `sub_15D4` 호출에서 twist가 먼저 돌아간다. 이걸 빼먹으면 수열이 8칸 밀려 시드를 영원히 못 찾는다.
- **twist의 제자리 갱신** — 상태를 복사해 두고 돌리면 `i >= 4`부터 값이 어긋난다. 반드시 in-place로 순차 갱신한다.

## 💥 Final Solver

```python
from pwn import *

HOST, PORT = "host3.dreamhack.games", 22690
DICT = "./dictionary.txt"
MASK = 0xFFFF

class Rng:
    def __init__(self, seed):
        s = [0] * 8
        s[0] = seed & MASK
        for i in range(1, 8):                       # sub_147B
            p = s[i - 1]
            s[i] = (27655 * (p ^ (p >> 14)) + i) & MASK
        self.s = s
        self.idx = 8                                # dword_4010 = 8 → 첫 호출에 twist

    def twist(self):                                # sub_1507
        s = self.s
        for i in range(8):
            nxt = s[(i + 1) % 8]
            v = ((s[i] & 0x8000) | (nxt & 0x7FFF)) >> 1
            if nxt & 1:
                v ^= 0x9908
            s[i] = (v ^ s[(i + 4) % 8]) & MASK
        self.idx = 0

    def next(self):                                 # sub_15D4
        if self.idx > 7:
            self.twist()
        v = self.s[self.idx]
        self.idx += 1
        n0, n1 = v & 0xF, (v >> 4) & 0xF
        n2, n3 = (v >> 8) & 0xF, (v >> 12) & 0xF
        return ((((5 * n0 + 6 * n1 + 4 * n2 + 7 * n3) & 0xF) << 12)
                | (((3 * n1 + 2 * n0 + 5 * n2 + 4 * n3) & 0xF) << 8)
                | (((6 * n2 + 7 * n1 + 4 * n0 + 3 * n3) & 0xF) << 4)
                | ((5 * n1 + 3 * n0 + 7 * n2 + 2 * n3) & 0xF))

def crack(words, easy):
    first = easy[0]
    for seed in range(1 << 16):
        r = Rng(seed)
        if words[r.next()] != first:
            continue
        if all(words[r.next()] == w for w in easy[1:]):
            return seed, r
    return None, None

def main():
    words = open(DICT).read().split()
    assert len(words) == 1 << 16, len(words)

    io = remote(HOST, PORT)

    easy = []
    for _ in range(10):                             # EASY: 단어가 그대로 보인다
        io.recvuntil(b"possible: ")
        w = io.recvline().strip().decode()
        easy.append(w)
        io.sendlineafter(b"> ", w.encode())
    log.success(f"easy: {easy}")

    seed, rng = crack(words, easy)
    assert seed is not None, "seed not found"
    log.success(f"seed = {seed:#06x}")

    hard = [words[rng.next()] for _ in range(10)]   # HARD: 예측
    log.success(f"hard: {hard}")
    for w in hard:
        io.sendlineafter(b"> ", w.encode())

    io.recvuntil(b"flag is ")
    print(io.recvall(timeout=3).decode(errors="replace"))

if __name__ == "__main__":
    main()
```

## 🚩 cat flag

```text
[+] Opening connection to host3.dreamhack.games on port 22690: Done
[+] easy: ['lactosuria', 'uppent', 'vasoreflex', 'exogastrically', 'progenitorial',
           'threadiness', 'Migonitis', 'maxillipedary', 'terebrant', 'potichomania']
[+] seed = 0xc51b
[+] hard: ['zooscopic', 'shan', 'Annonaceae', 'atmosteon', 'awalim',
           'lateroduction', 'stronghead', 'clacker', 'varnished', 'tailorization']
[+] Receiving all data: Done (59B)

DH{R3C0V3R4BL3_M3RS3NN3_V4R14N7:0Pscrj/2PdBOtJyeO6ILvA==}
```

플래그 본문 `R3C0V3R4BL3_M3RS3NN3_V4R14N7` = *recoverable Mersenne variant* — 의도된 취약점이 "복원 가능한 MT 변종"이었음을 확인해 준다.

## 🧠 Key Takeaways

- **난수의 비밀은 상태가 아니라 시드다.** 초기화 함수가 시드 하나에서 상태 전체를 유도하면, 상태 크기(128비트)는 의미가 없고 시드 크기(16비트)가 실제 보안 강도다.
- **캐스팅은 엔트로피를 버린다.** `read(fd, &buf, 4)`로 32비트를 받아도 `(unsigned __int16)`로 넘기면 `2^16`만 남는다. 시드 경로에서 `(char)`, `(short)`, `% N`, `& 0xFFFF` 같은 축소 연산을 먼저 찾아볼 것.
- **역산보다 전수조사가 쌀 때가 있다.** 공격 경로는 "가능한가"가 아니라 "싼가"로 고른다. 탐색 공간을 먼저 재고, 전수조사가 성립하면 복잡한 수식은 **그대로 옮겨서 정방향으로** 쓰면 된다.
- **표준 알고리즘의 축소판은 상수로 알아본다.** `0x9908`(MT19937의 `0x9908B0DF` 상위 16비트), `& 0x8000 | & 0x7FFF`(상위 1비트 + 하위 15비트 결합), `(i+1) % n` / `(i+m) % n` 참조 패턴이 MT twist의 지문이다.
- **출력이 가려지는 것과 값이 비밀인 것은 다르다.** `[REDACTED]`는 `printf`만 막았을 뿐 `strcmp` 대상은 그대로였다. 화면에서 지워진 값이 내부적으로도 보호되는지 항상 분리해서 볼 것.
