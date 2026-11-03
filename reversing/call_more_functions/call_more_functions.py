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
