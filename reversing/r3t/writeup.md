# ✏️ r3t

## 📄 Vulnerability & Code Analysis

stripped, non-PIE x86-64 ELF `run` 하나가 주어진다. 문자열은 다음 정도뿐이다.

```text
Input : 
%60s
Correct!
Wrong...
```

### main (0x402e46)

```asm
402e56:  call   printf                 ; "Input : "
402e6e:  call   __isoc99_scanf         ; "%60s" -> 0x6050e0
402e78:  call   0x402dca               ; 검사
402e7d:  movzx  eax,BYTE PTR [0x605124]
402e86:  je     Wrong
402e8f:  call   puts                   ; "Correct!"
```

### 검사 함수 0x402dca

```asm
402dd3:  call   0x400804               ; 길이 검사용 call chain
402dd8:  cmp    rbx,0xacac1a
402ddf:  jne    Wrong
402de5:  mov    DWORD PTR [0x605120],0x0   ; i = 0
402df1:  call   0x402db9               ; input[i] 변환
402e0b:  movzx  ecx,BYTE PTR [0x6050e0+i]
402e1f:  movzx  eax,BYTE PTR [0x605080+i]  ; 정답 테이블
402e23:  cmp    cl,al
402e25:  je     next
402e27:  jmp    Wrong
402e3e:  cmp    eax,0x3b               ; i <= 59
```

즉 다음과 같다.

```text
1. 길이 검사 (rbx == 0xacac1a)
2. i = 0..59 에 대해 input[i]를 변환한 뒤 0x605080[i]와 비교
```

### 핵심 트릭: leave 가젯으로 call chain 건너뛰기

이 바이너리의 함수는 대부분 아래처럼 다음 함수를 호출하기만 하는 1단짜리 래퍼다.

```asm
402db9:  push   rbp
402dba:  mov    rbp,rsp
402dc2:  call   0x402da8
402dc7:  nop
402dc8:  pop    rbp
402dc9:  ret
```

체인을 끝까지 따라가면 실제로 값을 바꾸는 함수가 나온다. 예를 들어 `0x402c3b`는 다음과 같다.

```asm
402c5c:  call   rand
402c74:  movzx  eax,BYTE PTR [0x6050e0+i]
402c7d:  add    edx,eax                ; input[i] += rand()
402c91:  mov    BYTE PTR [0x6050e0+i],cl

402c94:  mov    rax,QWORD PTR [rbp-0xc]
402c98:  lea    r15,ds:0x400803
402ca0:  and    rax,0x7
402ca4:  inc    rax
402ca7:  imul   rax,rax,0x6
402cab:  sub    r15,rax                ; r15 = 0x400803 - 6 * ((r & 7) + 1)
402cae:  call   r15
```

`0x4006d7`부터는 6바이트짜리 가젯이 연속으로 붙어 있다.

```asm
4006d7:  mov    QWORD PTR [rsp],rbp
4006db:  pop    rbp
4006dc:  leave
4006dd:  mov    QWORD PTR [rsp],rbp
4006e1:  pop    rbp
4006e2:  leave
...
```

`leave` 하나가 스택 프레임 하나를 걷어내므로, `call r15`로 이 가젯 중간에 뛰어들면 `(r & 7) + 1`개의 프레임을 한 번에 날리고 훨씬 위쪽 호출자로 돌아간다.

그래서 어떤 연산(`add`, `sub`, `xor` with `rand()`)이 몇 번, 어떤 순서로 실행될지가 `rand()` 값에 따라 정해진다. 정적으로 따라가기는 사실상 불가능하다.

`rand()`의 시드는 다음 바이트로 정해진다.

```asm
40116d:  mov    eax,DWORD PTR [0x605120]   ; i
401173:  add    eax,0x1
401180:  movzx  eax,BYTE PTR [0x6050e0+i+1]
401189:  call   srand                      ; srand(input[i+1])
```

결국 다음 성질이 성립한다.

```text
out[i] = F(input[i], input[i+1])
```

출력 바이트는 자기 자신과 바로 다음 바이트에만 의존하고, 위치 `i`에는 의존하지 않는다.

### 길이 검사

`0x400804`부터 시작하는 긴 call chain도 같은 가젯 트릭을 쓴다. 입력 길이에 따라 되감기 깊이가 달라지고, 특정 깊이의 함수(`0x400926`)에서만 `mov rbx,0xacac1a`가 실행된다.

gdb에서 `0x402dd8`에 bp를 걸고 길이별로 `rbx`를 찍어보면 44글자일 때만 통과한다.

```text
40 $1 = 0x0
44 $1 = 0xacac1a
50 $1 = 0x0
```

`DH{` + 40글자 + `}` = 44이므로 flag 본문은 40글자다.

### 취약점

```text
1. 각 출력 바이트가 (input[i], input[i+1]) 두 바이트에만 의존
2. 변환 함수 0x402db9를 gdb에서 직접 호출할 수 있음 (oracle)
3. 마지막 바이트 다음은 NUL(0)로 고정 → 뒤에서부터 확정 가능
```

## 🗡️ Exploit / Solver Strategy

난독화된 연산을 해석하지 않고, 변환 함수 자체를 oracle로 쓴다.

```text
1. 44글자 입력으로 실행해 길이 검사 통과
2. 비교 루프 0x402df1에서 정지
3. i = 0 으로 고정하고 input[0] = c, input[1] = next 를 써넣은 뒤
   call ((void(*)())0x402db9)() 로 변환 결과를 얻음
4. 모든 (c, next) 쌍(출력 가능 문자 + NUL)에 대해 테이블 T[next][c] 생성
5. 정답 테이블 0x605080에서 exp[0..43] 읽기
6. input[44] = NUL 에서 시작해 i = 43 → 0 으로 거꾸로 DFS
   T[input[i+1]][input[i]] == exp[i] 인 c만 이어 붙임
```

`out[i]`가 위치와 무관하므로 테이블은 `i = 0` 하나로 만들면 된다. gdb 호출 약 9,000번으로 6초 정도 걸린다.

DFS 결과 출력 가능한 해가 두 개 나온다.

```text
DH{<FLAG_REDACTED>}   ← 한 글자가 ']'
DH{<FLAG_REDACTED>}   ← 같은 자리가 hex 문자
```

두 해는 한 자리만 다르고, 둘 다 바이너리에서 `Correct!`가 나온다. 변환이 단사가 아니라서 생기는 충돌이다. flag 본문은 hex이므로 `]`가 아닌 hex 문자 쪽이 정답이다.

## 💻 Final Payload or Solver

`gdb`가 필요하다. (`./run`과 같은 디렉토리에서 실행)

```python
import json
import os
import re
import subprocess
import tempfile

BIN = "./run"
tmp = tempfile.mkdtemp()
inp = os.path.join(tmp, "in.txt")
out = os.path.join(tmp, "tab.json")
gscript = os.path.join(tmp, "g.py")

# 길이 검사(rbx == 0xacac1a)를 통과시키려면 44글자를 넣어야 비교 루프까지 간다
open(inp, "w").write("A" * 44 + "\n")

# 비교 루프(0x402df1)에서 멈춘 뒤, 변환 함수 0x402db9를 직접 호출해
# T[next][c] = transform(input[0] = c, input[1] = next) 테이블을 만든다
open(gscript, "w").write(f"""
import gdb, json
gdb.execute("b *0x402df1")
gdb.execute("r < {inp}")
inf = gdb.selected_inferior()
exp = bytes(inf.read_memory(0x605080, 60))

def T(c, n):
    inf.write_memory(0x605120, (0).to_bytes(4, "little"))  # idx = 0
    inf.write_memory(0x6050e0, bytes([c, n]))
    gdb.execute("call ((void(*)())0x402db9)()", to_string=True)
    return bytes(inf.read_memory(0x6050e0, 1))[0]

tab = {{n: [T(c, n) for c in range(32, 127)] for n in [0] + list(range(32, 127))}}
json.dump({{"exp": list(exp), "tab": tab}}, open("{out}", "w"))
""")
subprocess.run(["gdb", "-nx", "-q", "-batch", "-x", gscript, BIN], capture_output=True)

d = json.load(open(out))
exp = d["exp"]
tab = {int(k): v for k, v in d["tab"].items()}

# out[i]는 (in[i], in[i+1])에만 의존 → 끝의 NUL부터 거꾸로 DFS
sols = []

def go(i, nxt, suf):
    if i < 0:
        sols.append(suf)
        return
    for c in range(32, 127):
        if tab[nxt][c - 32] == exp[i]:
            go(i - 1, c, chr(c) + suf)

go(43, 0, "")
print(sols)

flag = next(s for s in sols if re.fullmatch(r"DH\{[0-9a-f]+\}", s))
print(flag)

res = subprocess.run([BIN], input=flag + "\n", capture_output=True, text=True).stdout
print(res)
```

## 🏳️ cat flag

DFS로 구한 hex 해를 실제 바이너리에 넣었을 때 `Correct!`가 출력되어 정답을 확인했다.

```
$ python3 r3t.py
['DH{<FLAG_REDACTED>}', 'DH{<FLAG_REDACTED>}']
DH{<FLAG_REDACTED>}
Input : Correct!
```
