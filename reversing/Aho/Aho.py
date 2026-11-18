#!/usr/bin/env python3
import struct
from pwn import ELF, process, remote, context

context.log_level = 'error'

REMOTE = True
HOST, PORT = 'host3.dreamhack.games', 15166

BIN        = '/home/kirin/pwnable_lab/reversing/Aho/main'
TABLE_ADDR = 0x4020
ALPHA_ADDR = 0x46B0
NSYM       = 10
NSTATE     = (ALPHA_ADDR - TABLE_ADDR) // (NSYM * 2 * 4)
LEN        = 13
GOAL       = 15

elf   = ELF(BIN, checksec=False)
alpha = elf.read(ALPHA_ADDR, NSYM).decode()
ints  = struct.unpack('<%di' % (NSTATE * NSYM * 2),
                      elf.read(TABLE_ADDR, NSTATE * NSYM * 2 * 4))

goto = [[ints[20 * s + 2 * j]     for j in range(NSYM)] for s in range(NSTATE)]
out  = [[ints[20 * s + 2 * j + 1] for j in range(NSYM)] for s in range(NSTATE)]

print('[*] alphabet : %r' % alpha)
print('[*] states   : %d' % NSTATE)
print('[*] outputs  : %s' % sorted({o for r in out for o in r if o >= 0}))

layers = [{(0, 0): None}]
for _ in range(LEN):
    nxt = {}
    for (s, m) in layers[-1]:
        for j in range(NSYM):
            o   = out[s][j]
            nm  = m | (1 << o) if o >= 0 else m
            key = (goto[s][j], nm)
            if key not in nxt:
                nxt[key] = ((s, m), j)
    layers.append(nxt)

end = next((k for k in layers[-1] if k[1] == GOAL), None)
assert end, 'no %d-char input reaches mask %d' % (LEN, GOAL)

ans, node = [], end
for i in range(LEN, 0, -1):
    node, j = layers[i][node]
    ans.append(alpha[j])
answer = ''.join(reversed(ans))
print('[+] answer   : %s' % answer)

p = remote(HOST, PORT) if REMOTE else process(['/lib64/ld-linux-x86-64.so.2', BIN])
p.sendlineafter(b'answer: ', answer.encode())
print('[+] %s' % p.recvall(timeout=5).decode().strip().replace('\n', ' | '))
p.close()
