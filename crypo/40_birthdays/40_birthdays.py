import hashlib
from tqdm import trange

def birthday_hash(msg):
    return hashlib.sha256(msg).digest()[12:17]

hash_list = []
hash_set = set()

for i in trange(2**21):
    msg = str(i).encode()
    result = birthday_hash(msg)

    if result in hash_set:
        msg1 = msg
        msg2 = str(hash_list.index(result)).encode()

        break

    hash_list.append(result)
    hash_set.add(result)

assert birthday_hash(msg1) == birthday_hash(msg2)

from pwn import *

io = remote("host3.dreamhack.games", 16793)

io.sendlineafter(b": ", bytes.hex(msg1).encode())
io.sendlineafter(b": ", bytes.hex(msg2).encode())

io.interactive()