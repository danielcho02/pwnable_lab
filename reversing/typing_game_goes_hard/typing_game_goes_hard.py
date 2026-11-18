from pwn import *

HOST, PORT = "host3.dreamhack.games", 22690
BIN  = "./chall"
DICT = "./dictionary.txt"

MASK = 0xFFFF

class Rng:

    def __init__(self, seed):
        s = [0] * 8
        s[0] = seed & MASK
        for i in range(1, 8):                       # sub_147B
            p = s[i - 1]
            s[i] = (27655 * (p ^ (p >> 14)) + i) & MASK
        self.s = s
        self.idx = 8                                # dword_4010 = 8 → 첫 호출에 twist

    def twist(self):                                # sub_1507
        s = self.s
        for i in range(8):
            nxt = s[(i + 1) % 8]
            v = ((s[i] & 0x8000) | (nxt & 0x7FFF)) >> 1
            if nxt & 1:
                v ^= 0x9908
            s[i] = (v ^ s[(i + 4) % 8]) & MASK
        self.idx = 0

    def next(self):                                 # sub_15D4
        if self.idx > 7:
            self.twist()
        v = self.s[self.idx]
        self.idx += 1
        n0, n1 = v & 0xF, (v >> 4) & 0xF
        n2, n3 = (v >> 8) & 0xF, (v >> 12) & 0xF
        return ((((5 * n0 + 6 * n1 + 4 * n2 + 7 * n3) & 0xF) << 12)
                | (((3 * n1 + 2 * n0 + 5 * n2 + 4 * n3) & 0xF) << 8)
                | (((6 * n2 + 7 * n1 + 4 * n0 + 3 * n3) & 0xF) << 4)
                | ((5 * n1 + 3 * n0 + 7 * n2 + 2 * n3) & 0xF))


def crack(words, easy):
    first = easy[0]
    for seed in range(1 << 16):
        r = Rng(seed)
        if words[r.next()] != first:
            continue
        if all(words[r.next()] == w for w in easy[1:]):
            return seed, r
    return None, None



def main():
    words = open(DICT).read().split()
    assert len(words) == 1 << 16, len(words)

    io = remote(HOST, PORT)

    easy = []
    for _ in range(10):                           
        io.recvuntil(b"possible: ")
        w = io.recvline().strip().decode()
        easy.append(w)
        io.sendlineafter(b"> ", w.encode())
    log.success(f"easy: {easy}")

    seed, rng = crack(words, easy)
    assert seed is not None, "seed not found"
    log.success(f"seed = {seed:#06x}")

    hard = [words[rng.next()] for _ in range(10)]  
    log.success(f"hard: {hard}")
    for w in hard:
        io.sendlineafter(b"> ", w.encode())

    io.recvuntil(b"flag is ")
    print(io.recvall(timeout=3).decode(errors="replace"))


if __name__ == "__main__":
    main()
