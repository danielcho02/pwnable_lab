#!/usr/bin/env python3
# similar - pwntools solver
#
# sub_16A3(x, y, z) = 1.0 - dot((x,y,z), (1,1,1)) / (|(x,y,z)| * sqrt(3))
#   -> (1,1,1) 과의 cosine distance   (0x2068 = 1.0)
#
# compar(a, b):
#   fa, fb = f(a), f(b);  eps = 1e-7            (0x2070 = 1e-7)
#   if fa - fb < eps: return 0
#   else:             return 1                  # -1 경로는 도달 불가 (dead code)
#
# 음수를 안 돌려주지만 glibc qsort 는 cmp > 0 만 보고 원소를 밀기 때문에
# 결과는 f 오름차순 안정 정렬과 동일하다. => 브루트포스 불필요.

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
