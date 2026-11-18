# ✏️ Aho

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 stripped PIE 바이너리 하나다.

```text
main: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

13글자를 받아서 맞으면 `flag`를 읽어준다.

```text
$ ./main
Give me your answer: hello
Impossible character on 5: 
```

### main

```c
printf("Give me your answer: ");
__isoc99_scanf("%13s", &v8);
v4 = 0;                                        // 상태
v5 = 0;                                        // 찾은 패턴 집합
for ( i = 0; i <= 12; ++i )
{
  for ( j = 0; j <= 9 && *((_BYTE *)&v8 + i) != byte_46B0[j]; ++j )
    ;                                          // 입력 문자 -> 알파벳 번호
  if ( j == 10 )
  {
    printf("Impossible character on %d: %c\n", i, *((char *)&v8 + i));
    exit(1);
  }
  if ( dword_4024[20 * v4 + 2 * j] >= 0 )
    v5 |= 1 << dword_4024[20 * v4 + 2 * j];    // 출력
  v4 = *((_DWORD *)&unk_4020 + 20 * v4 + 2 * j);  // 전이
}
if ( v5 == 15 )
{
  puts("Correct!");
  sub_1290();                                  // fopen("flag") 후 출력
}
```

루프 본문에 분기도 백트래킹도 없다. 문자 하나당 테이블 조회 두 번, 변수 두 개 갱신으로 끝난다. 전형적인 **DFA 구동 루프**다.

### 테이블의 모양

인덱스 `20 * v4 + 2 * j`가 구조를 전부 알려준다. `j`는 앞의 선형 탐색에서 나온 값이라 `0~9`, 따라서 `2 * j`는 최대 18 — 한 상태가 차지하는 폭이 정확히 20 int다.

```text
0x4020 ┌─────────── 한 행 = 한 상태, 20 int ───────────┐
       │ a      e      h      i   …   w                │
       │ ┌────┐ ┌────┐                                 │   한 칸 = int 2개
       │ │next│ │next│ …                               │   +0 : 다음 상태
       │ │out │ │out │                                 │   +4 : 출력 비트 번호 (-1 이면 없음)
       │ └────┘ └────┘                                 │
       └───────────────────────────────────────────────┘
0x46B0   byte_46B0[10] = "aehinrstuw"
```

`unk_4020`과 `dword_4024`는 같은 배열을 4바이트 차이로 가리키는 별명이다. 행 개수는 심볼 간격에서 바로 나온다.

```text
(0x46B0 - 0x4020) / 4 / 20 = 1680 / 80 = 21 개 상태
```

### Aho–Corasick

이 자료구조는 **여러 패턴을 한 번에 찾는** Aho–Corasick 자동자다. 패턴들을 트라이로 쌓아 각 노드를 상태로 삼고, 매칭이 어긋났을 때 "지금까지 읽은 것의 접미사"에 해당하는 상태로 점프하는 실패 링크를 미리 계산해 표에 녹여 넣는다. 그래서 실행 중에는 텍스트를 한 번만 훑으며 표만 따라가면 모든 패턴의 등장 여부가 나온다.

바이너리의 요소가 알고리즘의 요소와 1:1로 대응한다.

| Aho–Corasick | 바이너리 |
|---|---|
| 현재 상태 | `v4` |
| goto: 상태 × 문자 → 상태 | `unk_4020[20*v4 + 2*j]` |
| output: 패턴 번호 / 없음 | `dword_4024[...]` / `-1` |
| 찾은 패턴 집합 | `v5`의 비트 |

### 패턴 복원

상태 0에서 BFS로 각 상태의 최단 도달 문자열을 구하면 트라이가 그대로 되살아난다. 출력을 내는 전이는 8개, 즉 패턴은 4개가 아니라 **8개**다.

```text
root
 ├ t ─ h ─┬ i ─ s  ★0  this
 │        └ u ─ s  ★5  thus
 ├ s ─ i ─┬ s ─ a  ★1  sisa
 │        └ n ─ s  ★6  sins
 ├ a ─┬ n ─ s ─ w  ★2  answ
 │    └ s ─ i ─ a  ★7  asia
 ├ w ─ e ─ r ─ r   ★3  werr
 └ r ─ a ─ w ─ r   ★4  rawr
```

노드 20개 + 루트 1개 = 21개 상태로 딱 맞는다. 표 마지막 행(`0x4658`부터 `14h dup(0)`)은 어느 전이에서도 도달하지 않는 패딩이다.

여기서 조건의 진짜 의미가 드러난다. `v5 == 15`는 느슨한 `v5 & 15 == 15`가 아니다.

- **비트 0\~3** (`this` `sisa` `answ` `werr`) — 전부 등장해야 한다
- **비트 4\~7** (`rawr` `thus` `sins` `asia`) — 하나라도 등장하면 `v5 > 15`로 탈락

후자가 함정이다. 알파벳 `aehinrstuw`가 요구 패턴에 필요한 글자(`a e h i n r s t w`)에 `u`만 더한 구성인 것도 `thus`를 밟게 유도하려는 미끼다.

## 🗡️ Exploit / Solver Strategy

길이 13, 알파벳 10글자면 `10^13`가지다. 전수조사는 불가능하다.

핵심은 **프로그램이 기억하는 게 `v4`와 `v5` 둘뿐**이라는 점이다. `i`번째 글자 이후의 판정은 그때까지 무엇을 썼는지와 무관하게 이 두 값만으로 결정된다. 그리고 가능한 조합은

```text
v4 : 0~20  (21가지)        ×        v5 : 0~255  (실제 도달 가능 조합은 극소수)
```

이므로, 글자 수를 한 칸씩 늘려가며 도달 가능한 `(v4, v5)` 집합만 유지하면 된다. 같은 조합에 이르는 서로 다른 문자열은 이후 동작이 완전히 같으니 하나만 남기고 버린다. 탐색 공간이 `10^13`에서 수백 개로 줄어든다.

1. ELF에서 `0x4020`부터 1680바이트를 읽어 `goto` / `out` 두 테이블로 분리한다.
2. `(0, 0)`에서 시작해 13계층 BFS. 각 노드에 `(직전 노드, 사용한 문자)`를 기록한다.
3. 13번째 계층에서 `v5 == 15`인 노드를 찾아 역추적해 문자열을 복원한다.

`mask`를 하위 4비트로 잘라 쓰지 않는 것만 지키면 함정 비트는 자동으로 걸러진다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
import struct
from pwn import ELF, process, remote, context

context.log_level = 'error'

REMOTE = True
HOST, PORT = 'host3.dreamhack.games', 15166

BIN        = './main'
TABLE_ADDR = 0x4020
ALPHA_ADDR = 0x46B0
NSYM       = 10
NSTATE     = (ALPHA_ADDR - TABLE_ADDR) // (NSYM * 2 * 4)
LEN        = 13
GOAL       = 15

elf   = ELF(BIN, checksec=False)
alpha = elf.read(ALPHA_ADDR, NSYM).decode()
ints  = struct.unpack('<%di' % (NSTATE * NSYM * 2),
                      elf.read(TABLE_ADDR, NSTATE * NSYM * 2 * 4))

goto = [[ints[20 * s + 2 * j]     for j in range(NSYM)] for s in range(NSTATE)]
out  = [[ints[20 * s + 2 * j + 1] for j in range(NSYM)] for s in range(NSTATE)]

print('[*] alphabet : %r' % alpha)
print('[*] states   : %d' % NSTATE)
print('[*] outputs  : %s' % sorted({o for r in out for o in r if o >= 0}))

layers = [{(0, 0): None}]
for _ in range(LEN):
    nxt = {}
    for (s, m) in layers[-1]:
        for j in range(NSYM):
            o   = out[s][j]
            nm  = m | (1 << o) if o >= 0 else m
            key = (goto[s][j], nm)
            if key not in nxt:
                nxt[key] = ((s, m), j)
    layers.append(nxt)

end = next((k for k in layers[-1] if k[1] == GOAL), None)
assert end, 'no %d-char input reaches mask %d' % (LEN, GOAL)

ans, node = [], end
for i in range(LEN, 0, -1):
    node, j = layers[i][node]
    ans.append(alpha[j])
answer = ''.join(reversed(ans))
print('[+] answer   : %s' % answer)

p = remote(HOST, PORT) if REMOTE else process(['/lib64/ld-linux-x86-64.so.2', BIN])
p.sendlineafter(b'answer: ', answer.encode())
print('[+] %s' % p.recvall(timeout=5).decode().strip().replace('
', ' | '))
p.close()
```

PIE라 `ELF.read()`가 이미지 베이스 0 기준으로 읽어주므로 주소를 그대로 쓰면 된다. 로컬 검증은 바이너리 실행 권한을 건드리지 않도록 로더를 경유했다.

정답은 `thisisanswerr` — 요구 패턴 4개가 한 글자씩 겹쳐 사슬처럼 이어진다. 13글자가 최소 길이인 이유가 여기 있다.

```text
  t  h  i  s  i  s  a  n  s  w  e  r  r
  0  1  2  3  4  5  6  7  8  9 10 11 12
  └──this──┘
           └──sisa──┘
                    └──answ──┘
                             └──werr──┘
```

`this`의 `s`가 `sisa`의 시작이고, `sisa`의 `a`가 `answ`의 시작이며, `answ`의 `w`가 `werr`의 시작이다. 실패 링크 없이는 이런 겹침을 한 번의 스캔으로 잡아낼 수 없다. 문제가 Aho–Corasick을 고른 이유이자, 제목이 `Aho`인 이유다.

## 🏳️ cat flag

```text
$ /home/kirin/.venv/pwn/bin/python3 Aho.py
[*] alphabet : 'aehinrstuw'
[*] states   : 21
[*] outputs  : [0, 1, 2, 3, 4, 5, 6, 7]
[+] answer   : thisisanswerr
[+] Correct! | Flag is: DH{<FLAG_REDACTED>}
```
