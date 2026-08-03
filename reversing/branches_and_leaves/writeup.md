# ✏️ branches_and_leaves

> https://dreamhack.io/wargame/challenges/1750

## 📄 Vulnerability & Code Analysis

`main`은 인자 하나를 받아 `sub_11E0`로 검사한 뒤, 검사를 통과하면 입력을 그대로 출력한다.

```c
if ( a1 == 2 )
{
    v4 = a2[1];
    sub_11E0(v4, a2, a3);
    __printf_chk(1LL, "DH{%s}\n", v4);   // 통과한 입력이 그대로 flag
}
```

즉 검사를 통과하는 입력 자체가 flag다. 별도의 복호화나 변형이 없다.

`sub_11E0`의 로직은 다음과 같다.

- 입력 길이는 정확히 64여야 한다. (`strlen(a1) != 64` 이면 `exit(1)`)
- 입력을 4글자씩 16개 그룹으로 나눈다.
- 각 그룹의 4글자를 16진수(`0-9`, `a-f`만 허용)로 파싱해 16비트 값 `v4`를 만든다.
- 이 16비트를 **LSB부터** 한 비트씩 읽으며 트리 `dword_4060`을 16번 타고 내려간다.
  - `result = dword_4060[2 * result + bit]`, 시작 노드는 `0`
  - 중간 노드는 `result == -1` 이거나 `result > 0x3FFFF` 이면 무효 처리되어 `exit(1)`
- 16스텝 후의 최종값(leaf)이 `dword_4020[그룹번호]`와 같아야 통과한다.

핵심 자료구조는 두 개다.

```
dword_4020[16]   : 각 그룹이 도달해야 하는 목표 leaf 값 (16개)
dword_4060[...]  : 2진 트리. 노드 n의 자식은 dword_4060[2*n], dword_4060[2*n+1]
```

문제 이름 그대로, 16비트 경로(branch)를 따라 내려가 목표 leaf에 도달하는지를 검사하는 거대한 결정 트리다.

보호기법 자체는 풀이에 영향이 없다. (참고: amd64, PIE, Full RELRO, NX)

## 🗡️ Exploit / Solver Strategy

각 그룹은 서로 독립적이다. 그룹 `i`는 오직 자신의 16비트 값이 트리를 타고 `dword_4020[i]`에 도달하기만 하면 된다.

트리를 역방향으로 추적할 필요 없이, 한 그룹의 후보는 16비트 = `0x10000`개뿐이므로 전부 정방향으로 시뮬레이션해서 `leaf -> 16비트 값` 역매핑을 한 번만 만들면 된다. 16개 목표를 이 역매핑에서 찾아 `%04x`로 되돌리면 64글자 입력이 완성된다.

구현할 때 걸린 지점은 세 가지였다.

- **트리 크기**: IDA가 `dword_4060`을 `[61415]`로 라벨했지만 실제 배열은 훨씬 크다. `tree[0]`부터 이미 `0x11A3E`(≈72254)라 노드 인덱스가 그 크기를 넘어간다. bound가 `result <= 0x3FFFF`인 것에서 배열이 약 `0x7FFFF`개 규모임을 알 수 있으므로, `dword_4060`이 속한 섹션을 통째로 읽어야 한다.
- **bound 조건**: 원본은 `result > 0x3FFFF`가 무효 → 유효 범위는 `0 <= result <= 0x3FFFF`. 자릿수(`0x3FFFF`, F 5개)와 경계(`<=`)를 정확히 맞춰야 한다.
- **인덱스 가드**: 잘못된 후보는 `result`가 커져 `2*result+bit`가 배열 밖을 가리킬 수 있으므로, 인덱싱 전에 범위를 검사해 무효 처리한다. 이걸 빼면 `IndexError`가 난다.

또한 16번째(마지막) 스텝은 원본에서 bound 검사 없이 최종 leaf 값을 그대로 두므로, 시뮬레이터도 마지막 스텝에서만 검사를 건너뛰어야 목표 leaf 값(큰 값)과 비교할 수 있다.

## 💻 Final Payload or Solver

```python
from pwn import *
import struct

e = ELF('./main')

targets = [u32(e.read(0x4020 + 4 * i, 4)) for i in range(16)]

TREE_ADDR = 0x4060
sec = next(s for s in e.sections
           if s.header.sh_addr <= TREE_ADDR < s.header.sh_addr + s.header.sh_size)
end = sec.header.sh_addr + sec.header.sh_size
raw = e.read(TREE_ADDR, end - TREE_ADDR)
tree = list(struct.unpack('<%di' % (len(raw) // 4), raw))

def walk(x):
    result = 0
    for step in range(16):
        bit = x & 1
        x >>= 1
        idx = 2 * result + bit
        if not (0 <= idx < len(tree)):
            return None
        result = tree[idx]
        if step != 15 and not (0 <= result <= 0x3FFFF):
            return None
    return result

rev = {}
for x in range(0x10000):
    y = walk(x)
    if y is not None:
        rev.setdefault(y, x)

flag = ''.join('%04x' % rev[t] for t in targets)
print('DH{%s}' % flag)

io = process(['./main', flag])
print(io.recvall().decode())
```

`process`로 복원한 입력을 실제 바이너리에 다시 넣어, 동일한 `DH{...}`가 출력되는지로 정답을 검증한다.

## 🏳️ cat flag

16개 그룹이 모두 역매핑에서 풀려 64글자 입력이 복원되었고, 바이너리에 넣었을 때 동일한 문자열이 그대로 출력되어 정답을 확인했다.

```
(.venv) (base) ➜  branches_and_leaves pypwn branches_and_leaves.py
[*] '/home/daniel/dreamhack/rev/branches_and_leaves/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
[*] tree entries: 524288
DH{d8f794325872bab95cfaa117545c6c0b77059a74f4dd31d8c2bf130a59745d77}
[+] Starting local process './main': pid 12416
[+] Receiving all data: Done (69B)
[*] Process './main' stopped with exit code 0 (pid 12416)
DH{d8f794325872bab95cfaa117545c6c0b77059a74f4dd31d8c2bf130a59745d77}
```
