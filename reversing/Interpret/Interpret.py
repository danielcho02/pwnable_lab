#!/usr/bin/env python3
from pwn import *

HOST, PORT = "host3.dreamhack.games", 21574

QWORDS = [
    0x050504B003750201, 0x038A0201E0070000,
    0x200C000005040471, 0x0502047703F10201,
    0x03CA020138050000, 0x00120000050604A5,
    0x052F035602040401, 0x0240030169020000,
    0x100F000005040446, 0x050704D702340301,
    0x02C0030180D90000, 0xA01F000005050405,
    0x05C203DC02030401, 0x02070401BE020000,
    0x8E1F0000050F0381, 0x0502045702190301,
    0x03CD020160020000, 0x00050000050504FC,
    0x050304F303CB0201, 0x02010401700E0000,
    0xF7020000058703C8, 0x05C6039A02030401,
    0x03AD0201D4050000, 0xB20200000501047D,
]
CODE = b"".join(q.to_bytes(8, "little") for q in QWORDS) + b"\x00"

HALT, LOADKEY, ADD, XOR, ROL, CMP = range(6)
M32 = 0xFFFFFFFF


def rol32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32 if n else x & M32


def disasm(code):
    out, pc = [], 0
    while pc < len(code):
        op = code[pc]
        pc += 1
        if op == HALT:
            out.append((op, None))
            break
        if op in (ADD, XOR, ROL):
            out.append((op, code[pc]))
            pc += 1
        elif op == CMP:
            out.append((op, int.from_bytes(code[pc:pc + 4], "big")))
            pc += 4
        elif op == LOADKEY:
            out.append((op, None))
        else:
            break
    return out


def solve(prog):
    key, acc_ops, pending = [], [], False
    for op, imm in prog:
        if op == LOADKEY:
            acc_ops, pending = [], True
        elif op in (ADD, XOR, ROL):
            acc_ops.append((op, imm))
        elif op == CMP:
            if not pending:
                continue
            for cand in range(256):
                acc = cand
                for o, v in acc_ops:
                    if o == ADD:
                        acc = (acc + v) & M32
                    elif o == XOR:
                        acc ^= v
                    else:
                        acc = rol32(acc, v)
                if acc == imm:
                    key.append(cand)
                    break
            else:
                raise RuntimeError(f"key[{len(key)}] not found")
            pending = False
    return bytes(key)


def emulate(code, key):
    acc, pc, ki = 0, 0, 0
    while pc < len(code):
        op = code[pc]; pc += 1
        if op == HALT:
            return 1
        if op == LOADKEY:
            if ki > 15:
                return 0
            acc = key[ki]; ki += 1
        elif op in (ADD, XOR, ROL):
            if pc >= len(code):
                return 0
            imm = code[pc]; pc += 1
            acc = (acc + imm) & M32 if op == ADD else acc ^ imm if op == XOR else rol32(acc, imm)
        elif op == CMP:
            if pc + 3 >= len(code):
                return 0
            if acc != int.from_bytes(code[pc:pc + 4], "big"):
                return 0
            pc += 4
        else:
            return 0
    return 1


def main():
    assert len(CODE) == 0xC1, len(CODE)
    prog = disasm(CODE)
    key = solve(prog)
    assert len(key) == 16, key
    assert emulate(CODE, key) == 1, "self-check failed"
    log.success(f"key = {key.hex()}")

    io = remote(HOST, PORT)
    io.sendlineafter(b"hex): ", key.hex().encode())
    print(io.recvall(timeout=5).decode(errors="replace"))


if __name__ == "__main__":
    main()
