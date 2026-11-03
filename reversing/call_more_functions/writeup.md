# ✏️ call_more_functions

## 📄 Vulnerability & Code Analysis

stripped x86-64 PIE `main` 하나가 주어진다. 눈에 띄는 문자열은 다음 두 개뿐이다.

```text
Input: 
Correct! The flag is DH{%s}
```

### main

```asm
1fbf:  lea    rbx,[rip+0x307a]        # 0x5040 (input)
1fd5:  call   __isoc99_scanf          # "%65s"
1fdd:  call   strlen
1fe7:  cmp    rax,0x40                # 길이 64
1ff6:  call   0x1311                  # 검사 함수
1ffd:  test   eax,eax
1fff:  jne    fail
2019:  call   __printf_chk            # "Correct! The flag is DH{%s}"
```

입력 64글자가 검사를 통과하면 입력 그대로 `DH{...}` 안에 출력된다. 즉 통과하는 입력 자체가 flag다.

### 검사 함수 0x1311 = 작은 스택 VM

`0x1311`은 분기 없이 `mov edi, imm` + `call`이 수백 번 반복되는 함수다. 호출 대상은 네 개뿐이다. (전역 스택 `0x50a0`, 스택 포인터 `0x508c`, 실패 플래그 `0x5088`)

```asm
; 0x1236  push(imm)
mov    BYTE PTR [rcx+rdx*1],dil      ; stack[sp] = edi
add    eax,0x1                       ; sp++

; 0x1257  load
movzx  ecx,BYTE PTR [rdx+rax*1]      ; idx = stack[sp-1]
movzx  ecx,BYTE PTR [rsi+rcx*1]      ; input[idx]
mov    BYTE PTR [rdx+rax*1],cl       ; stack[sp-1] = input[idx]

; 0x1290  xor
xor    BYTE PTR [rdx+rax*1],sil      ; stack[sp-2] ^= stack[sp-1]; sp--

; 0x12cb  cmp
cmp    BYTE PTR [rcx+rsi*1],al       ; stack[sp-2] != stack[sp-1] ?
setne  al
or     DWORD PTR [rip+0x3d8c],eax    ; fail |= mismatch; sp--
```

정리하면 다음과 같다.

```text
0x1236 : push(imm)
0x1257 : top = input[top]
0x1290 : a, b = pop2;  push(a ^ b)
0x12cb : a, b = pop2;  fail |= (a != b)
```

`0x1311`은 마지막에 `fail`(0x5088)을 반환하고, 0이어야 Correct가 출력된다.

함수 끝부분을 보면 입력 바이트 여러 개를 load해서 xor로 모두 접은 뒤, 상수와 cmp하는 패턴이 반복된다.

```asm
1f62:  call   0x1290     ; xor
1f6c:  call   0x1290     ; xor
1f76:  call   0x1290     ; xor
1f7b:  mov    edi,0x0
1f80:  call   0x1236     ; push 0
1f8a:  call   0x12cb     ; cmp
```

`load` 64번, `cmp` 64번이 있으므로 64개 입력 바이트에 대한 XOR 등식 64개가 된다.

```text
input[i1] ^ input[i2] ^ ... ^ input[ik] == const   (64개)
```

### 취약점

```text
1. 검사 로직이 직선형 VM 바이트코드라 그대로 추출 가능
2. 모든 제약이 XOR 선형식 → SMT/연립방정식으로 바로 풀림
3. 통과한 입력이 곧 flag
```

## 🗡️ Exploit / Solver Strategy

손으로 수백 개 호출을 따라갈 필요 없이, `objdump` 출력에서 `mov edi, imm`와 `call` 대상만 순서대로 뽑으면 VM 명령 리스트가 된다.

```text
1. 0x1311 ~ 0x1f8f 디스어셈블
2. call 대상(0x1236/0x1257/0x1290/0x12cb)과 직전 edi 값을 명령 리스트로 변환
3. 입력 64바이트를 z3 BitVec(8)로 두고 스택을 심볼릭하게 실행
4. cmp마다 등식 제약 추가
5. sat 모델을 문자열로 변환
6. 실제 바이너리에 넣어 Correct 확인
```

`load`의 인덱스는 항상 바로 앞에서 push한 상수이므로 `as_long()`으로 바로 꺼낼 수 있다.

## 💻 Final Payload or Solver

`binutils(objdump)`, `z3-solver`가 필요하다.

```python
import re
import subprocess

from z3 import BitVec, BitVecVal, Solver, sat

PUSH, LOAD, XOR, CMP = 0x1236, 0x1257, 0x1290, 0x12CB

dis = subprocess.run(
    ["objdump", "-d", "-M", "intel", "./main",
     "--start-address=0x1311", "--stop-address=0x1f8f"],
    capture_output=True,
    text=True,
    check=True,
).stdout

ops = []
arg = None
for line in dis.splitlines():
    m = re.search(r"mov\s+edi,0x([0-9a-f]+)", line)
    if m:
        arg = int(m.group(1), 16)
    m = re.search(r"call\s+([0-9a-f]+)", line)
    if m:
        ops.append((int(m.group(1), 16), arg))

x = [BitVec("x%d" % i, 8) for i in range(64)]
s = Solver()
for v in x:
    s.add(v >= 0x21, v <= 0x7E)

stack = []
for op, arg in ops:
    if op == PUSH:
        stack.append(BitVecVal(arg, 8))
    elif op == LOAD:
        # 바로 앞에서 push한 상수가 인덱스
        stack[-1] = x[stack[-1].as_long()]
    elif op == XOR:
        b = stack.pop()
        stack[-1] = stack[-1] ^ b
    elif op == CMP:
        b = stack.pop()
        s.add(stack[-1] == b)

assert s.check() == sat
m = s.model()
flag = bytes(m[v].as_long() for v in x).decode()
print("DH{%s}" % flag)

out = subprocess.run(["./main"], input=flag + "\n", capture_output=True, text=True).stdout
print(out)
```

## 🏳️ cat flag

z3가 구한 입력을 실제 바이너리에 넣었을 때 Correct가 출력되어 정답을 확인했다.

```
$ python3 call_more_functions.py
DH{<FLAG_REDACTED>}
Input: Correct! The flag is DH{<FLAG_REDACTED>}
```
