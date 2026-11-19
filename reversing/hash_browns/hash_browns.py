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
