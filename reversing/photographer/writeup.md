# ✏️ photographer

## 📄 Vulnerability & Code Analysis

문제 파일은 stripped x86-64 C++ ELF `prob`와 암호화된 이미지 `flag.bmp.enc` 두 개다.

`strings`로 보면 다음 문자열이 있다.

```text
flag.bmp
flag.bmp.enc
Can't open flag bitmap file.
create file is failed.
```

즉 `prob`가 `flag.bmp`를 읽어 암호화한 뒤 `flag.bmp.enc`로 저장하는 구조다.

`flag.bmp.enc`의 크기는 6,220,854바이트이다.

```text
54 + 1920 * 1080 * 3 = 6220854
```

BMP 헤더(54바이트) + 1920x1080 24bit 픽셀 데이터와 정확히 일치하므로, 암호화가 크기를 바꾸지 않는 바이트 단위 변환임을 알 수 있다.

### 시드 고정

`nm -D prob`로 보면 `srand`, `rand`를 import한다. main 시작 부분은 다음과 같다.

```asm
251a:  mov    edi,0xbeef
251f:  call   srand@plt
```

시드가 상수 `0xbeef`이므로 `rand()` 수열은 매번 같다.

### 회전 헬퍼 함수

`0x2489`와 `0x24c2`에 회전 함수 두 개가 있다.

```asm
; 0x2489
and    DWORD PTR [rbp-0x8],0x7   ; k &= 7
sar    edx,cl                    ; b >> k
...
shl    edx,cl                    ; b << (8 - k)
or     eax,esi
```

```text
0x2489 = ror(b, k)
0x24c2 = rol(b, k)   (shl / sar 순서만 반대)
```

### 암호화 루프

파일 전체를 벡터로 읽은 뒤 인덱스 `i`마다 `i % 3`으로 분기한다. (`0xaaaaaaaaaaaaaaab` 곱셈은 컴파일러가 만든 `/3` 최적화)

```asm
; i % 3 == 0
26bf:  call   ror           ; ror(b, 7) = rol(b, 1)
26c6:  call   rand@plt
26cb:  add    eax,ebx       ; + rand()
26d7:  call   rol           ; rol(x, 4)

; i % 3 == 1
26fe:  call   rand@plt
2709:  and    eax,0x7       ; rand() % 8
2733:  call   ror           ; ror(b, rand() % 8)

; i % 3 == 2
2775:  call   rand@plt
277a:  xor    eax,ebx       ; b ^ rand()
277c:  lea    ebx,[rax-0x18]; - 0x18
```

정리하면 다음과 같다. (`r = rand()`, 결과는 byte로 저장)

```text
i % 3 == 0 : c = rol((rol(b, 1) + r) & 0xff, 4)
i % 3 == 1 : c = ror(b, r % 8)
i % 3 == 2 : c = ((b ^ r) - 0x18) & 0xff
```

어느 분기든 바이트마다 `rand()`를 정확히 한 번 호출한다.

### 취약점

```text
1. srand 시드가 상수 → keystream이 고정
2. 각 연산(회전, 덧셈, XOR, 뺄셈)이 모두 가역
3. BMP 헤더가 알려진 평문이라 복호화 검증이 쉬움
```

## 🗡️ Exploit / Solver Strategy

glibc `rand()`를 그대로 재현해야 하므로 `ctypes`로 `libc.so.6`의 `srand`, `rand`를 직접 호출한다.

각 분기를 역순으로 되돌린다.

```text
i % 3 == 0 : b = ror((ror(c, 4) - r) & 0xff, 1)
i % 3 == 1 : b = rol(c, r % 8)
i % 3 == 2 : b = ((c + 0x18) & 0xff) ^ (r & 0xff)
```

복호화 결과의 첫 2바이트가 `BM`이면 성공이다. 실제로 헤더는 다음처럼 복원된다.

```text
424d36ec5e000000000036000000280000008007000038040000010018...
flag.bmp: PC bitmap, Windows 3.x format, 1920 x 1080 x 24
```

이미지에는 흰 배경에 검은 글씨로 flag가 3줄에 걸쳐 적혀 있다. 텍스트 영역만 잘라 `tesseract`로 OCR한다.

OCR이 `7` 하나를 `/`로 잘못 읽는데, flag 본문은 hex라 `/`가 올 수 없으므로 `7`로 보정한다.

## 💻 Final Payload or Solver

Linux(glibc) 환경에서 `Pillow`, `tesseract-ocr`가 필요하다.

```python
import ctypes
import re
import subprocess

from PIL import Image

libc = ctypes.CDLL("libc.so.6")
libc.srand(0xBEEF)

rol = lambda b, k: ((b << k) | (b >> (8 - k))) & 0xFF if k else b
ror = lambda b, k: ((b >> k) | (b << (8 - k))) & 0xFF if k else b

ct = open("flag.bmp.enc", "rb").read()
pt = bytearray(len(ct))

for i, c in enumerate(ct):
    r = libc.rand()
    if i % 3 == 0:
        pt[i] = ror((ror(c, 4) - r) & 0xFF, 1)
    elif i % 3 == 1:
        pt[i] = rol(c, r % 8)
    else:
        pt[i] = ((c + 0x18) & 0xFF) ^ (r & 0xFF)

assert pt[:2] == b"BM"
open("flag.bmp", "wb").write(pt)

Image.open("flag.bmp").convert("L").crop((80, 217, 1830, 761)).save("crop.png")
txt = subprocess.run(
    ["tesseract", "crop.png", "-", "--psm", "6"],
    capture_output=True,
    text=True,
    check=True,
).stdout

# tesseract가 '7' 하나를 '/'로 읽는다 (hex에는 '/'가 없음)
flag = re.sub(r"\s", "", txt).replace("/", "7")
print(re.search(r"DH\{[0-9a-f]{64}\}", flag).group(0))
```

## 🏳️ cat flag

복호화된 `flag.bmp`가 정상 BMP로 열리고, OCR 결과가 이미지에 적힌 flag와 일치한다.

```
$ python3 photographer.py
DH{<FLAG_REDACTED>}
```
