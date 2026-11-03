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
