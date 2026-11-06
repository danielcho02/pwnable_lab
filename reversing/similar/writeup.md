# ✏️ similar

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 stripped PIE 바이너리 하나다.

```text
similar: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

실행하면 `/dev/urandom`으로 시드를 잡아 랜덤 3차원 벡터 30개를 뿌리고, 어떤 순서를 요구한다.

```text
Values:
0: -34 12 87
1: 5 -91 -2
...
29: 63 63 -7
Result?
```

### main

```c
fd = open("/dev/urandom", O_RDONLY);
read(fd, &buf, 4);
srand(buf);                                  // 시드 예측 불가
puts("Values:");
for ( i = 0; i <= 29; ++i )
{
  base[4 * i]     = rand() % 200 - 100;      // x
  base[4 * i + 1] = rand() % 200 - 100;      // y
  base[4 * i + 2] = rand() % 200 - 100;      // z
  base[4 * i + 3] = i;                       // 원래 index
  printf("%d: %d %d %d\n", i, base[4*i], base[4*i+1], base[4*i+2]);
}
qsort(base, 0x1E, 0x10, compar);             // 16바이트 원소 30개
puts("Result?");
for ( j = 0; j <= 29; ++j )
{
  __isoc99_scanf("%d", &n);
  if ( base[4 * j + 3] != (_DWORD)n )        // 정렬 후의 index 순서
  {
    puts("Wrong...");
    return 0;
  }
}
// 전부 맞으면 ./flag 를 읽어서 출력
```

원소는 `{int x, int y, int z, int index}` 16바이트 구조체다. 벡터 성분만 출력되고 index는 출력되지 않지만, 처음에는 `index == i`이므로 `i`번째 줄의 벡터가 index `i`를 들고 있다는 걸 알 수 있다.

요구되는 입력은 **`compar` 기준으로 정렬한 뒤의 index 나열**이다. 시드가 `/dev/urandom`이라 랜덤 예측은 불가능하고, 30!가지 순서를 때려 맞출 수도 없다. 결국 `compar`를 그대로 재현하는 게 유일한 길이다.

`alarm(60)`이 걸려 있어 수동 입력으로는 시간이 빡빡하다.

### 정렬 키: sub_16A3 (0x16A3)

`compar`가 각 원소마다 부르는 헬퍼다. 디컴파일이 지저분해서 어셈블리로 보는 게 빠르다.

```asm
16d0:  movl   $0x1,-0x10(%rbp)      ; b = {1, 1, 1}  (함수 내부 고정)
16d7:  movl   $0x1,-0xc(%rbp)
16de:  movl   $0x1,-0x8(%rbp)
...
1718:  call   sqrt                  ; na = sqrt(1*1 + 1*1 + 1*1) = sqrt(3)
...
1759:  call   sqrt                  ; nb = sqrt(x*x + y*y + z*z)
1767:  ...                          ; dot = x*1 + y*1 + z*1
179e:  mulsd  -0x28(%rbp),%xmm2     ; xmm2 = nb * na
17ac:  divsd  %xmm2,%xmm1           ; xmm1 = dot / (nb * na)   <- 코사인 유사도
17b0:  movsd  0x8b0(%rip),%xmm0     ; 0x2068 = 1.0
17b8:  subsd  %xmm1,%xmm0           ; return 1.0 - cos
```

`.rodata`에서 상수 두 개를 확인할 수 있다.

```text
 2060 00000000 00000000 00000000 0000f03f   ; 0x2068 = 1.0
 2070 48afbc9a f2d77a3e                     ; 0x2070 = 1e-7
```

정리하면 고정 벡터 `(1, 1, 1)`과의 **코사인 거리**다.

```c
double f(int x, int y, int z) {
    return 1.0 - (x + y + z) / (sqrt(x*x + y*y + z*z) * sqrt(3));
}
```

문제 이름 `similar`가 cosine similarity를 가리킨다.

### compar (0x17C8) — `-1`을 안 돌려주는 비교 함수

```asm
1810:  call   16a3                  ; fa = f(a)
182c:  call   16a3                  ; fb = f(b)
183a:  movsd  0x82e(%rip),%xmm0     ; eps = 1e-7
1850:  subsd  -0x30(%rbp),%xmm1     ; xmm1 = fa - fb
185a:  comisd %xmm1,%xmm0           ; cmp eps, (fa - fb)
185e:  jbe    1867
1860:  mov    $0x0,%eax             ; eps > fa - fb  ->  return 0
1865:  jmp    187f
1867:  movsd  -0x30(%rbp),%xmm0     ; fb
186c:  comisd -0x38(%rbp),%xmm0     ; cmp fb, fa
1871:  jbe    187a
1873:  mov    $0xffffffff,%eax      ; return -1   <- 도달 불가
1878:  jmp    187f
187a:  mov    $0x1,%eax             ; return 1
```

C로 옮기면 이렇다.

```c
int compar(const void *a, const void *b) {
    double fa = f(a), fb = f(b);
    if (fa - fb < 1e-7) return 0;
    return 1;              // fb > fa 분기(-1)는 여기선 성립할 수 없다
}
```

`-1` 경로는 `fa - fb >= 1e-7`, 즉 `fa > fb`일 때만 도달하는데 그 조건에서는 항상 `fb <= fa`라 `jbe`가 먹힌다. 결과적으로 **이 비교 함수는 0과 1만 돌려준다.**

처음엔 이게 함정이라고 생각했지만, glibc `qsort`는 비교 결과가 `> 0`인지만 보고 원소를 뒤로 미는 구조다. 음수와 0을 구분하지 않으므로

- `0` = "a가 b보다 작거나 같다"
- `1` = "a가 b보다 크다"

로 완전히 일관된 순서가 되고, 결과는 **`f` 오름차순 정렬**과 같다.

`1e-7`은 동일 키 허용 오차다. 랜덤 값에서 `1e-7` 이내로 붙는 경우는 사실상 방향이 완전히 같은 벡터(예: `(1,2,3)`과 `(3,2,1)` 같은 성분 순열, 또는 `(1,2,3)`과 `(2,4,6)` 같은 스칼라배)뿐이고, 그때는 안정 정렬 순서가 정답이 된다. Python `sorted`가 stable이라 그대로 맞는다.

### 취약점

취약점이라기보다 정렬 키를 복원하는 문제다. 랜덤 시드는 `/dev/urandom`에서 와서 예측할 수 없지만, **값이 전부 출력되기 때문에** 비교 함수만 재현하면 매 라운드 정답을 바로 계산할 수 있다. 브루트포스는 필요 없다.

## 🗡️ Exploit / Solver Strategy

1. `Values:` 이후 30줄을 파싱해 `index -> (x, y, z)` 매핑을 만든다.
2. 각 벡터의 키 `1 - (x+y+z) / (sqrt(x²+y²+z²) · sqrt(3))`를 계산한다.
3. 키 오름차순으로 **stable sort** 하고, 그 순서대로 원래 index를 출력한다.
4. `Result?` 다음에 index 30개를 개행으로 구분해 보낸다.

`(0,0,0)`이 나오면 `nb = 0`이라 0 나눗셈으로 `NaN`이 된다. `comisd`는 unordered일 때 CF/ZF를 모두 세워 양쪽 `jbe`가 다 먹히므로 `compar`는 `1`(= 항상 큼)을 돌려준다. 솔버에서도 키를 `inf`로 둬서 맨 뒤로 보냈다. 확률은 1/8,000,000 수준이라 실제로 볼 일은 없다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
from math import sqrt
from pwn import *

p = remote("host3.dreamhack.games", 20534)
# p = process("./similar")


def key(v):
    """compar 가 쓰는 정렬 키: (1,1,1) 과의 cosine distance."""
    x, y, z = v
    n = sqrt(x * x + y * y + z * z)
    if n == 0:
        return float("inf")  # (0,0,0) -> NaN, comisd unordered 라 항상 뒤로
    return 1 - (x + y + z) / (n * sqrt(3))


p.recvuntil(b"Values:\n")

values = [None] * 30
for _ in range(30):
    idx, rest = p.recvline().decode().split(":")
    values[int(idx)] = tuple(map(int, rest.split()))

order = sorted(range(30), key=lambda i: key(values[i]))
print("[*] order:", order)

p.recvuntil(b"Result?\n")
for i in order:
    p.sendline(str(i).encode())

print(p.recvall(timeout=5).decode().strip())
```

로컬 바이너리로 60회 연속 돌려 60/60 성공을 확인한 뒤 원격에 붙였다.

## 🏳️ cat flag

```text
$ python similar.py
[+] Opening connection to host3.dreamhack.games on port 20534: Done
[*] order: [5, 2, 14, 23, 25, 1, 29, 8, 4, 9, 16, 20, 3, 22, 7, 10, 6, 11, 15, 21, 26, 28, 18, 19, 12, 24, 0, 13, 27, 17]
[+] Receiving all data: Done (60B)
Bingo! Flag: DH{<FLAG_REDACTED>}
```

플래그 본문에 `c0s1n3`이 들어 있어 의도된 풀이가 코사인 유사도 정렬이었음을 확인할 수 있다.
