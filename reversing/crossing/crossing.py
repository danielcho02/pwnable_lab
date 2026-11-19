#!/usr/bin/env python3
"""crossing (DreamHack rev) solver.

main은 입력 파일의 각 바이트를 상/하위 니블로 쪼개 "단어"로 만들고,
NxN 격자에 크로스워드처럼 가로/세로로 무작위 배치한다.

단어 i (i = 니블 순번, 0부터)의 바이트열:
    FF | base253(i+1) 각 자리 +2 (little-endian) | FF | 0x01 * (nibble+1) | FF

겹침은 값이 같은 칸에서만 허용되므로 모든 단어는 격자에서 원형 그대로 읽힌다.
따라서 격자의 모든 행/열에서 위 패턴을 찾아 순번과 니블 값을 복원하면 된다.
"""
import re
import sys
import math

BASE = 253
DIGIT_BIAS = 2
SEP = 0xFF
FILL = 0x01

PATTERN = re.compile(rb'(?=\xff([\x02-\xfe]+)\xff(\x01+)\xff)', re.DOTALL)


def decode_digits(digits: bytes) -> int:
    """little-endian base-253, 각 자리 +2 → 원래 값 (= index + 1)"""
    value = 0
    for pos, raw in enumerate(digits):
        value += (raw - DIGIT_BIAS) * (BASE ** pos)
    return value


def harvest(line: bytes, nibbles: dict) -> None:
    for m in PATTERN.finditer(line):
        idx = decode_digits(m.group(1)) - 1
        nib = len(m.group(2)) - 1
        if idx < 0 or nib > 0xF:
            continue
        # 종단 FF 뒤에 다른 단어의 0x01이 이어 붙으면 0x01 런이 길게 보일 수
        # 있다. 반대로 짧아지는 일은 없으므로(겹침은 같은 값에서만) 최솟값이 참값.
        prev = nibbles.get(idx)
        nibbles[idx] = nib if prev is None else min(prev, nib)


def solve(path: str) -> bytes:
    grid = open(path, 'rb').read()
    n = int(math.isqrt(len(grid)))
    if n * n != len(grid):
        raise ValueError(f'격자 크기가 완전제곱이 아니다: {len(grid)}')

    rows = [grid[r * n:(r + 1) * n] for r in range(n)]
    cols = [bytes(grid[r * n + c] for r in range(n)) for c in range(n)]

    nibbles = {}
    for line in rows:
        harvest(line, nibbles)
    for line in cols:
        harvest(line, nibbles)

    count = len(nibbles)
    if sorted(nibbles) != list(range(count)):
        missing = [i for i in range(max(nibbles) + 1) if i not in nibbles]
        raise ValueError(f'니블 누락: {missing[:20]}')
    if count % 2:
        raise ValueError('니블 개수가 홀수다')

    return bytes((nibbles[2 * i] << 4) | nibbles[2 * i + 1]
                 for i in range(count // 2))


if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else 'flag.jpg.crossing'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'flag.jpg'
    data = solve(src)
    open(dst, 'wb').write(data)
    print(f'[+] {len(data)} bytes -> {dst}')
