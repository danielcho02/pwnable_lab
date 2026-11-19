# ✏️ hash-browns

> Category: reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 stripped PIE 바이너리 하나다.

```text
hash-browns: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

실행하면 입력을 한 줄 받고 맞는지만 알려준다.

```text
$ ./hash-browns
Input : asdf
Wrong!
```

맞으면 `Correct! Flag is %s`로 **입력을 그대로** 되돌려준다. 즉 입력이 곧 플래그고, 바이너리는 검증기 역할만 한다.

임포트 목록이 짧아서 먼저 본다.

```text
read  strchr  memcmp  printf  puts  fflush
```

비교가 `strcmp`가 아니라 `memcmp`다. NUL이 섞여도 되는 고정 길이 블롭을 비교한다는 뜻이고, 문제 이름까지 같이 보면 해시 다이제스트다.

### 해시 식별 — 0x1209

```asm
1231:  movl   $0x67452301,0x8(%rax)
123c:  movl   $0xefcdab89,0xc(%rax)
1247:  movl   $0x98badcfe,0x10(%rax)
1252:  movl   $0x10325476,0x14(%rax)
```

MD4/MD5/RIPEMD 계열의 초기 상태다. 상태가 네 워드뿐이라 SHA-1(다섯 워드)은 빠진다.

0x15b3의 압축 함수를 보면 라운드 함수가 네 종류다.

```asm
15ea:  mov -0xc(%rbp),%eax ; and -0x8(%rbp) ...   ; F = (b&c) | (~b&d)
196b:  mov -0x10(%rbp),%eax ; and -0x8(%rbp) ...  ; G = (d&b) | (~d&c)
1c82:  xor -0x8(%rbp),%eax ; xor -0x4(%rbp)       ; H = b^c^d
201a:  not %eax ; or -0xc(%rbp),%eax ; xor ...    ; I = c ^ (b|~d)
```

상수도 첫 몇 개만 맞춰 보면 바로 나온다. `sub`로 쓰여 있어서 2의 보수를 취해야 한다.

```text
1609:  sub $0x28955b88  ->  add 0xd76aa478   K[0]
163e:  sub $0x173848aa  ->  add 0xe8c7b756   K[1]
1673:  add $0x242070db                       K[2]
```

로테이션 값은 처음에 변형 해시인가 싶게 생겼다.

```text
라운드 1   rol 7   rol 12   ror 15   ror 10
라운드 2   rol 5   rol  9   rol 14   ror 12
라운드 3   rol 4   rol 11   rol 16   ror  9
라운드 4   rol 6   rol 10   rol 15   ror 11
```

`rol n`은 `ror 32-n`과 같은 연산이다. 보수를 취하면 7/12/17/22, 5/9/14/20, 4/11/16/23, 6/10/15/21 — MD5 표준 시프트 그대로다. 컴파일러가 더 짧은 인코딩을 고른 것뿐이다. **순정 MD5**다.

### 길이 패딩이 없어 보이는 부분

0x13e7의 final 함수는 버퍼를 14워드(56바이트)만 채우고 압축 함수를 부른다.

```asm
14dd:  cmpl   $0xd,-0x60(%rbp)      ; i <= 13 까지만
14e1:  jbe    146e
14f5:  mov    %rdx,%rdi             ; transform(state, &block)
14fa:  call   15b3
```

처음엔 패딩 버그라고 생각했는데, 스택 레이아웃을 보면 아니다. 블록 배열은 `[rbp-0x50]`에서 시작하는 16워드고, 15·16번째 워드 자리가 바로 함수 진입부에서 비트 카운트를 복사해 둔 `[rbp-0x18]`, `[rbp-0x14]`다.

```asm
140a:  mov    (%rax),%eax           ; count[0]
140c:  mov    %eax,-0x18(%rbp)      ; = block[14]
1413:  mov    0x4(%rax),%eax        ; count[1]
1416:  mov    %eax,-0x14(%rbp)      ; = block[15]
```

길이 인코딩을 명시적으로 쓰지 않고 **스택 인접성에 맡긴** 구현이다. 동작은 표준 MD5와 같다. 여기서 "커스텀 해시다"로 새면 뒤가 다 틀어지는 지점이었다.

### main — 0x22b9

```c
unsigned char expect[9][16] = { /* 0x22d7 부터 movabs 18개로 박힌 144바이트 */ };
char buf[256] = {0};

printf("Input : "); fflush(stdout);
read(0, buf, 0x100);
char *nl = strchr(buf, '\n');
if (nl) *nl = 0;

for (int i = 0; i <= 8; i++) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf + 3 * i, 3);
    MD5_Final(&ctx);
    if (memcmp(ctx.digest, expect[i], 16) != 0) {
        puts("Wrong!");
        return 1;
    }
}
buf[27] = 0;
printf("Correct! Flag is %s\n", buf);
```

루프 경계가 핵심이다.

```asm
25d9:  imul   -0x21c(%rbp),%eax     ; 3 * i
25e9:  lea    (%rdx,%rax,1),%rcx    ; buf + 3*i
25cf:  mov    $0x3,%esi             ; 길이 3
2601:  call   125c                  ; MD5_Update
262a:  shl    $0x4,%rdx             ; i * 16
2648:  call   1100                  ; memcmp(digest, expect + i*16, 16)
2671:  cmp    $0x8,%eax             ; i <= 8, 총 9회
```

### 취약점

MD5를 쓴 게 아니라 **쪼개 쓴 게** 문제다. 플래그 27바이트를 한 번에 해싱하지 않고 3바이트 블록 아홉 개로 나눠 각각 해싱했고, 블록끼리 체이닝도 없다. 그래서 블록 하나를 틀려도 나머지에 영향이 없고, 각 블록을 독립적으로 전수조사할 수 있다.

탐색 공간이 `95^27`에서 `9 x 95^3`, 약 770만으로 줄어든다. 출력 가능 ASCII 3바이트면 86만 가지니 테이블 한 번 만들어 두고 아홉 번 조회하면 끝난다. ECB 모드가 블록 단위로 평문 구조를 노출하는 것과 같은 실수다.

## 🗡️ Exploit / Solver Strategy

1. 0x22d7부터 이어지는 `movabs` 18개(= qword 18개 = 144바이트)를 긁는다.
2. 리틀엔디안으로 직렬화해 16바이트씩 자르면 다이제스트 아홉 개가 나온다.
3. 출력 가능 ASCII 3바이트 조합 전체(`95^3 = 857,375`)의 MD5를 미리 계산해 `digest -> chunk` 역테이블을 만든다.
4. 아홉 개 타깃을 순서대로 조회해 이어 붙인다.

테이블 생성이 1초 안쪽이라 최적화할 게 없다. `movabs`는 `mov QWORD PTR [rbp-...], rax` 쌍으로 들어가므로, 저장 오프셋이 `-0x1a0`에서 8씩 증가하는지만 확인하면 순서를 그대로 믿을 수 있다.

## 💻 Final Payload or Solver

```python
#!/usr/bin/env python3
"""hash-browns 솔버.

27바이트 입력을 3바이트 블록 9개로 나눠 각각 MD5를 돌리고 하드코딩된
다이제스트와 memcmp 한다. 블록당 95**3 가지뿐이라 블록별로 전수조사한다.
"""
import hashlib
import itertools
import string
import struct

# main() 0x22d7 에서 긁은 qword 18개 = MD5 다이제스트 9개
QWORDS = [
    0xFE5D3A093968D02B, 0xBA0AA367C2862EAE,
    0x8BEA2ADA9E26604F, 0x2E6F41C96DCF5224,
    0x7FD91BD2949B75F3, 0x05B1ED8E6072F3A6,
    0xC94045C6D4887611, 0x9D43DF6DF6B94D95,
    0xB9A8A83C8AC08D80, 0x6D78E80376518464,
    0x0E81A20F2023C2D0, 0x2E41EAE69D89F186,
    0x425C831DD2A3E5FD, 0x82788DBBDC4100EC,
    0x6D0FEE8D3901DD20, 0xEBE82A0A41E5D783,
    0x2AFA26414B72E506, 0x0D1848E9C21D114D,
]

blob = b"".join(struct.pack("<Q", q) for q in QWORDS)
targets = [blob[i:i + 16] for i in range(0, len(blob), 16)]

ALPHABET = (string.ascii_letters + string.digits + string.punctuation).encode()

table = {}
for trio in itertools.product(ALPHABET, repeat=3):
    chunk = bytes(trio)
    table[hashlib.md5(chunk).digest()] = chunk

flag = b""
for i, target in enumerate(targets):
    chunk = table.get(target)
    if chunk is None:
        raise SystemExit(f"chunk {i} not found: {target.hex()}")
    flag += chunk

print(flag.decode())
```

## 🏳️ cat flag

솔버가 뱉은 문자열을 그대로 바이너리에 먹여 확인했다.

```text
$ python hash_browns.py
DH{<FLAG_REDACTED>}

$ echo 'DH{<FLAG_REDACTED>}' | ./hash-browns
Input : Correct! Flag is DH{<FLAG_REDACTED>}
```

플래그 본문이 md5가 약하다는 내용이라, 의도된 교훈도 해시 선택이 아니라 사용 방식이었던 것으로 보인다. 긴 비밀을 블록으로 쪼개 각각 해싱하면 전체 강도는 가장 짧은 블록 수준으로 내려간다. 비밀번호라면 전체를 한 번에, 솔트와 KDF(bcrypt, argon2)를 같이 써야 한다.
