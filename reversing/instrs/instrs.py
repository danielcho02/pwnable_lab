#!/usr/bin/env python3
# instrs - solver
#
# prob 은 8바이트짜리 프로그램을 읽어 간단한 VM 으로 돌리고,
# "실행한 명령어 개수"를 Result 로 출력한다. 그 값이 99999 보다 크면 flag 를 준다.
#
#   prog[8] @ 0x4050   mem[8] @ 0x4060   pc @ 0x406c   dp @ 0x4070
#
# ISA (pc, dp 는 0..7 로 clamp, mem 은 u8)
#   '+'  mem[dp]++
#   '-'  mem[dp]--
#   'l'  dp--            (0 에서 더 못 내려감)
#   'r'  dp++            (7 에서 더 못 올라감)
#   'n'  nop
#   'a'  mem[dp] != 0 이면 pc = 0 (프로그램 처음으로), 0 이면 그냥 다음 명령
#   'e'  halt -> 지금까지 실행한 명령어 수를 리턴
#   그 외 바이트는 전부 "No Hack!" + exit(-1)
#
# 'a' 가 "프로그램 맨 앞으로 점프"라서 루프 바디는 항상 prog[0] 부터다.
# 'a' 두 개를 쓰면 안쪽 루프가 끝난 뒤(셀이 0) 아래로 흘러 두 번째 'a' 가
# 다른 셀로 바깥 루프를 돌리는 2중 루프가 된다.
#
#   l   dp = 0                 <- 바깥 루프에서 돌아왔을 때 dp 복구
#   -   mem[0]--               0 -> 255 (u8 wrap) 이므로 256 번 돌아야 0
#   a   mem[0] != 0 -> goto 0  안쪽 루프 (3 명령 x 256 회 = 768)
#   r   dp = 1
#   -   mem[1]--
#   a   mem[1] != 0 -> goto 0  바깥 루프 (771 명령 x 256 회)
#   e   halt
#
# 총 256 * 771 + 1 = 197377 스텝 > 99999.
# alarm(5) 이 걸려 있지만 20만 스텝은 순식간이라 문제없다.

from pwn import *

PROGRAM = b'l-ar-ae'  # 7바이트, read(0, prog, 8) 안에 들어간다


def simulate(prog):
    """바이너리 없이 스텝 수를 미리 계산해 보는 참고용 시뮬레이터."""
    prog = prog.ljust(8, b'\x00')
    mem = [0] * 8
    pc = dp = steps = 0
    while True:
        op = prog[pc]
        steps += 1
        halt = False
        if op == ord('+'):
            mem[dp] = (mem[dp] + 1) & 0xFF
        elif op == ord('-'):
            mem[dp] = (mem[dp] - 1) & 0xFF
        elif op == ord('l'):
            dp = max(dp - 1, 0)
        elif op == ord('r'):
            dp = min(dp + 1, 7)
        elif op == ord('n'):
            pass
        elif op == ord('a'):
            if mem[dp] != 0:
                pc = 0
                continue
        elif op == ord('e'):
            halt = True
        else:
            raise ValueError('No Hack! (invalid op %r)' % chr(op))
        if halt:
            return steps
        pc = min(pc + 1, 7)


log.info('simulated steps: %d', simulate(PROGRAM))

p = remote("host3.dreamhack.games", 14977)
# p = process("./prob")

p.recvuntil(b"Enter Your Program\n")
p.send(PROGRAM)

print(p.recvall(timeout=10).decode(errors="replace").strip())
