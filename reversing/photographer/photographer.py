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
