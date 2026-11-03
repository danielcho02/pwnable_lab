# ✏️ timetravel3

> Category: misc / reversing

## 📄 Vulnerability & Code Analysis

배포 파일은 7z 하나이고, 풀면 다음 세 파일이 나온다.

```text
mspaint03.run   1.3GB   TTD 트레이스
mspaint03.idx   1.16GB  TTD 인덱스
mspaint03.out   2KB     TTDRecord 로그
```

`mspaint03.out`을 보면 Windows 10(19045) x64에서 `C:\Windows\System32\mspaint.exe`를 TTD(Time Travel Debugging)로 약 83초 동안 녹화한 것이다.

```text
Microsoft (R) TTDRecord 1.01.11 x64
Running "C:\Windows\System32\mspaint.exe"
Simulation time of '"C:\Windows\System32\mspaint.exe" ' (x64): 83141ms.
Trace dumped to C:\Users\Incognito\Documents\mspaint03.run
```

정석 풀이는 WinDbg로 트레이스를 열어 시간을 오가며 그림판이 받은 입력을 보는 것이다. 여기서는 WinDbg 없이 `.run` 원본을 직접 파싱했다.

### 문자열로는 안 나온다

`strings`로 `{`, flag, 경로 등을 찾아도 flag는 나오지 않는다.

대신 상태바에 찍히는 마우스 좌표 문자열(`123, 456px`)이 대량으로 보인다. 사용자가 캔버스 위에서 마우스를 움직였다는 뜻이다. 즉 flag는 그림판에 **마우스로 직접 그린 손글씨**일 가능성이 높다.

하지만 상태바 문자열은 순서가 섞여 있고 조각나 있어서, 그대로 찍으면 글자가 되지 않는다.

### `.run` 레코드 구조

`.run` 파일은 압축되어 있지 않다. 대부분이 44바이트 고정 크기의 메모리 읽기 레코드다.

```text
offset  size  내용
0       1     타입 (0x14 = 데이터 읽기, 0x15 = 코드)
1       1     0x00
2       2     ?
4       8     주소 (32바이트 정렬)
12      32    그 주소의 메모리 내용
```

주소의 상위 바이트가 0이라서 offset 10, 11이 항상 `00 00`이 된다. 이 조건으로 레코드 경계를 쉽게 검증할 수 있다.

레코드는 파일에 시간 순서대로 쌓이므로, 특정 주소의 레코드만 모아서 순서대로 보면 그 메모리가 시간에 따라 어떻게 바뀌었는지 알 수 있다.

### 그림판의 메시지 루프 MSG 찾기

마우스 입력은 결국 `MSG` 구조체로 메시지 루프에 들어온다.

```c
typedef struct tagMSG {
    HWND   hwnd;     // +0x00
    UINT   message;  // +0x08
    WPARAM wParam;   // +0x10
    LPARAM lParam;   // +0x18  (y << 16) | x
    DWORD  time;     // +0x20
    POINT  pt;       // +0x24
} MSG;               // 48 bytes
```

레코드 데이터에서 `message`가 `WM_LBUTTONDOWN(0x201)`이고 바로 앞 qword가 그럴듯한 hwnd인 위치를 주소별로 세면, 캔버스 창 hwnd `0xe0592`와 함께 다음 전역 주소가 가장 많이 나온다.

```text
0x7ff6c357e808   mspaint 메시지 루프의 전역 MSG
```

`mspaint.exe` 이미지 영역(`0x7ff6...`)에 있는 전역 변수이므로, `GetMessage`가 매번 채우는 메인 루프의 MSG로 볼 수 있다.

### MSG가 두 라인에 걸쳐 있다

MSG는 48바이트이고 `0x...e808`에서 시작하므로, 32바이트 라인 두 개(`0x...e800`, `0x...e820`)에 걸쳐 있다.

레코드가 한 라인씩 따로 기록되기 때문에, 한쪽만 갱신된 중간 상태가 섞인다. 예를 들어 `message`는 새 값인데 `lParam`은 이전 값인 상태가 생긴다.

그래서 **lParam이 새로 바뀐 순간**의 마우스 메시지만 점으로 인정하도록 필터링했다.

```text
hwnd == 0xe0592
message in (WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP)
lParam != 직전 lParam
```

### 획 복원

```text
WM_LBUTTONDOWN               → 새 획 시작
WM_MOUSEMOVE (wParam & 1)    → 왼쪽 버튼을 누른 채 이동, 획에 점 추가
WM_LBUTTONUP                 → 획 종료
```

이렇게 하면 버튼 down/up이 정확히 64쌍 나온다. 획 64개를 선으로 이어 그리면 손글씨가 그대로 복원된다.

녹화 중 Windows가 마우스 이동 메시지를 합쳐서(coalescing) 보내기 때문에 획이 약간 각져 보이지만, 읽는 데는 문제없다.

### 취약점

```text
1. TTD 트레이스에는 프로세스가 읽은 메모리가 전부 평문으로 남는다
2. .run 레코드가 압축되지 않은 고정 크기 구조라 리플레이 엔진 없이도 파싱 가능
3. 그림판이 받은 마우스 메시지(MSG)를 시간순으로 따라가면 그린 내용을 그대로 재현 가능
```

## 🗡️ Exploit / Solver Strategy

```text
1. MSG가 걸친 두 라인 주소(0x...e800, 0x...e820)를 little-endian 바이트로 검색
2. 매치 위치 - 4가 레코드 시작인지 헤더(0x14, 0x00, offset 10/11 == 0)로 검증
3. 레코드를 파일 순서(= 시간 순서)로 적용하면서 MSG 48바이트를 재구성
4. 캔버스 hwnd의 마우스 메시지 중 lParam이 바뀐 순간만 점으로 채택
5. down / move(MK_LBUTTON) / up 으로 획을 나눠 PIL로 그림
6. strokes.png를 눈으로 읽기
```

1.3GB 전체를 레코드 단위로 걷지 않고, 필요한 주소 패턴만 정규식으로 찾기 때문에 20초 정도면 끝난다.

## 💻 Final Payload or Solver

`Pillow`가 필요하다. (`mspaint03.run`과 같은 디렉토리에서 실행)

```python
import mmap
import re
import struct
import sys

from PIL import Image, ImageDraw

RUN = sys.argv[1] if len(sys.argv) > 1 else "mspaint03.run"

MSG_ADDR = 0x7FF6C357E808  # mspaint 메시지 루프의 전역 MSG
CANVAS_HWND = 0xE0592
WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP = 0x200, 0x201, 0x202

# MSG(48바이트)가 걸쳐 있는 32바이트 라인 두 개
lines = [MSG_ADDR & ~31, (MSG_ADDR + 32) & ~31]

f = open(RUN, "rb")
m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

# 메모리 읽기 레코드: 14 00 ?? ?? | addr(8) | data(32) = 44바이트
# addr 앞 4바이트가 헤더라서 addr 값으로 검색한 뒤 4바이트 앞으로 돌아간다
pat = re.compile(b"|".join(re.escape(struct.pack("<Q", l)) for l in lines))
recs = []
for mo in pat.finditer(m):
    p = mo.start() - 4
    if p < 0 or m[p] != 0x14 or m[p + 1] != 0 or m[p + 10] != 0 or m[p + 11] != 0:
        continue
    addr = struct.unpack("<Q", m[p + 4:p + 12])[0]
    recs.append((p, addr, m[p + 12:p + 44]))
recs.sort()

# 파일 순서 = 시간 순서. 두 라인을 갱신하면서 MSG 값의 변화를 기록
mem = {l: b"\0" * 32 for l in lines}
events = []
prev = None
for _, addr, data in recs:
    mem[addr] = data
    buf = (mem[lines[0]] + mem[lines[1]])[MSG_ADDR - lines[0]:][:36]
    hwnd, msg, wparam, lparam, _t = struct.unpack("<QIxxxxQQI", buf)
    if (hwnd, msg, wparam, lparam) == prev:
        continue
    prev = (hwnd, msg, wparam, lparam)
    events.append((hwnd, msg, wparam, lparam))

# MSG가 두 라인에 걸쳐 있어 한쪽만 갱신된 중간 상태가 섞인다
# → lParam이 새로 바뀐 순간의 캔버스 마우스 메시지만 점으로 인정
points = []
plp = None
for hwnd, msg, wparam, lparam in events:
    if (lparam != plp and hwnd == CANVAS_HWND
            and msg in (WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP)
            and lparam >> 32 == 0 and lparam != 0):
        points.append((msg, wparam, lparam & 0xFFFF, lparam >> 16))
    plp = lparam

strokes = []
down = False
for msg, wparam, x, y in points:
    if msg == WM_LBUTTONDOWN:
        cur = [(x, y)]
        strokes.append(cur)
        down = True
    elif msg == WM_MOUSEMOVE and wparam & 1:  # MK_LBUTTON
        if not down:
            cur = []
            strokes.append(cur)
            down = True
        cur.append((x, y))
    elif msg == WM_LBUTTONUP:
        if down:
            cur.append((x, y))
        down = False
    else:
        down = False

print("strokes:", len(strokes))

im = Image.new("L", (1300, 560), 255)
d = ImageDraw.Draw(im)
for s in strokes:
    if len(s) == 1:
        x, y = s[0]
        d.ellipse([x - 2, y - 2, x + 2, y + 2], fill=0)
    else:
        d.line(s, fill=0, width=4)
im.save("strokes.png")
print("saved strokes.png")
```

## 🏳️ cat flag

획 64개가 모두 복원되었고, 이미지에 세 줄짜리 손글씨가 나온다.

```
$ python3 timetravel3.py
strokes: 64
saved strokes.png
```

```text
The flag is
INCOGNITO{<FLAG_REDACTED>}
```
