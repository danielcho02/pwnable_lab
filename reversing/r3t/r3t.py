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
