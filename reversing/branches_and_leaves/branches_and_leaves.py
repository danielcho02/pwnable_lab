from pwn import *
import struct

e = ELF('./main')

targets = [u32(e.read(0x4020 + 4 * i, 4)) for i in range(16)]

# dword_4060이 속한 섹션을 통째로 읽는다 (배열이 61415보다 훨씬 큼)
TREE_ADDR = 0x4060
sec = next(s for s in e.sections
           if s.header.sh_addr <= TREE_ADDR < s.header.sh_addr + s.header.sh_size)
end = sec.header.sh_addr + sec.header.sh_size
raw = e.read(TREE_ADDR, end - TREE_ADDR)
tree = list(struct.unpack('<%di' % (len(raw) // 4), raw))   # signed int
print('[*] tree entries:', len(tree))

def walk(x):
    result = 0
    for step in range(16):
        bit = x & 1
        x >>= 1
        idx = 2 * result + bit
        if not (0 <= idx < len(tree)):
            return None
        result = tree[idx]
        if step != 15 and not (0 <= result <= 0x3FFFF):   # 0x3FFFF (5F), <=
            return None
    return result

rev = {}
for x in range(0x10000):
    y = walk(x)
    if y is not None:
        rev.setdefault(y, x)

# 어느 그룹이 안 풀렸는지 먼저 확인 (디버그용)
missing = [i for i, t in enumerate(targets) if t not in rev]
if missing:
    print('[!] unresolved groups:', missing)
else:
    flag = ''.join('%04x' % rev[t] for t in targets)
    print('DH{%s}' % flag)
    io = process(['./main', flag])   # 실제 바이너리로 검증
    print(io.recvall().decode())