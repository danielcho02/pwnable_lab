from pwn import *
import re

p = remote("host1.dreamhack.games", 12486)

def make_spell(n):
    bits = bin(n)[2:]

    spell = "A"

    for b in bits[1:]:
        spell += "B"
        if b == "1":
            spell += "A"

    return spell

for _ in range(10):
    data = p.recvuntil(b"Cast your spell!: ").decode()

    m = re.search(
        r"HP:\s*(\d+), STR:\s*(\d+), AGI:\s*(\d+), VIT:\s*(\d+), INT:\s*(\d+), END:\s*(\d+), DEX:\s*(\d+)",
        data
    )

    hp = int(m.group(1))
    str_ = int(m.group(2))
    agi = int(m.group(3))
    vit = int(m.group(4))
    int_ = int(m.group(5))
    end = int(m.group(6))
    dex = int(m.group(7))

    n = (hp << 48) | (dex << 40) | (end << 32) | (int_ << 24) | (vit << 16) | (agi << 8) | str_

    spell = make_spell(n)

    p.sendline(spell.encode())

p.interactive()