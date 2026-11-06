#!/usr/bin/env python3
# CrabME - solver
#
# chal::hex_to_u32_vec  : 입력이 정확히 64글자, 전부 [0-9a-f] 인지 검사한 뒤
#                         2글자씩 묶어 u32 32개로 만든다.
# chal::flagchecker     : vec.len() == 32 확인 후, 각 바이트에 대해
#                           1) 비트 퍼뮤테이션  in bit i -> out bit PERM[i]
#                           2) ^= 0x63
#                           3) += 0x22  (u8 wrap)
#                         결과를 .rodata(0x49000) 의 u32 테이블 32개와 비교.
#
# 바이트 단위로 독립적이고 전사(injective) 라서 256개 역테이블만 만들면 끝난다.

import subprocess
import sys

# flagchecker 0x80E1~0x8135 의 비트 이동: 입력 bit i -> 출력 bit PERM[i]
PERM = [3, 0, 4, 1, 7, 6, 2, 5]

# .rodata 0x49000 (u32 x 32)
EXPECTED = [
    0xAE, 0x6D, 0x9B, 0x92, 0x13, 0x2B, 0xC6, 0xC9,
    0xE5, 0xFA, 0x96, 0x0B, 0x64, 0x31, 0xB8, 0x08,
    0xC8, 0x48, 0xD2, 0x30, 0x60, 0x04, 0xFA, 0x7B,
    0x88, 0xB0, 0x2F, 0x7C, 0xB3, 0xB3, 0x58, 0x61,
]


def forward(v):
    """flagchecker 가 입력 바이트 한 개에 적용하는 변환."""
    out = 0
    for i in range(8):
        if v >> i & 1:
            out |= 1 << PERM[i]
    out ^= 0x63
    return (out + 0x22) & 0xFF


def main():
    table = {forward(v): v for v in range(256)}
    assert len(table) == 256, 'not injective'

    answer = ''.join('%02x' % table[e] for e in EXPECTED)
    print('[*] input :', answer)
    print('[*] flag  : DH{%s}' % answer)

    if len(sys.argv) > 1:
        out = subprocess.run([sys.argv[1]], input=(answer + '\n').encode(),
                             capture_output=True).stdout.decode()
        print('[*] verify:', out.strip())


if __name__ == '__main__':
    main()
