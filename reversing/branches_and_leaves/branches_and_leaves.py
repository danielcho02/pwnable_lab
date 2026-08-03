from pwn import *
import struct

e = ELF('./main')

targets = [u32(e.read(0x4020 + 4 * i, 4)) for i in range(16)]

TREE_ADDR = 0x4060
sec = next(s for s in e.sections
           if s.header.sh_addr <= TREE_ADDR < s.header.sh_addr + s.header.sh_size)
end = sec.header.sh_addr + sec.header.sh_size
raw = e.read(TREE_ADDR, end - TREE_ADDR)
tree = list(struct.unpack('<%di' % (len(raw) // 4), raw))  
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
        if step != 15 and not (0 <= result <= 0x3FFFF): 
            return None
    return result

rev = {}
for x in range(0x10000):
    y = walk(x)
    if y is not None:
        rev.setdefault(y, x)

missing = [i for i, t in enumerate(targets) if t not in rev]
if missing:
    print('[!] unresolved groups:', missing)
else:
    flag = ''.join('%04x' % rev[t] for t in targets)
    print('DH{%s}' % flag)
    io = process(['./main', flag])   
    print(io.recvall().decode())
