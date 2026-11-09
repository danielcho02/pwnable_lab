#!/usr/bin/env python3
# Honest - solver
#
# ./main <flag> 형태. 플래그 길이는 64 이고, 바이트마다 calculate() 를 거친 값이
# 체인상의 각 함수에 하드코딩된 상수와 같아야 한다.
#
# 함정: _start 가 __libc_start_main 에 넘기는 "main" 은 main 이 아니라
#       verify_func_28 이다.
#
#   10d8:  lea 0x12f1(%rip),%rdi    # 23d0 <verify_func_28>
#   10df:  call *0x4ef3(%rip)       # __libc_start_main
#
# 실제 진입점은 verify_func_28 이고, main 은 그냥 체인의 56번째(index 55) 고리다.
# 각 함수는 전역 counter 를 ++ 하면서 argv[1][counter] 를 검사하므로
# "체인 실행 순서 = 플래그 인덱스" 가 된다.
#
# 각 고리의 공통 구조:
#   if (argc != 2) { puts("How to use: ./main <flag>"); exit(0); }
#   c = argv[1][counter++];
#   if (calculate(c) != <상수>) correct = 0;
#   if (counter > 0x3f) return 0;
#   <다음 함수>(argc, argv, envp);
#   (main 만 추가로 strlen(argv[1]) == 0x40 검사 + 결과 출력)
#
# 그래서 objdump 로 각 함수의 (cmp 상수, 다음 함수)만 뽑아
# verify_func_28 부터 64칸 따라가면 상수 배열이 순서대로 나온다.

import re
import subprocess
import sys

BIN = './main'
ENTRY = 'verify_func_28'  # _start 가 __libc_start_main 에 넘기는 함수


def calculate(c):
    """calculate (0x11A9) 재현. 전단사라 역테이블을 만들 수 있다."""
    x = c ^ 0x3C
    x = ((x << 2) | (x >> 6)) & 0xFF        # rol 2
    x = (x * 5 + 0x7D) & 0xFF
    x = ((x >> 3) | (x << 5)) & 0xFF        # ror 3
    x ^= 0xB2
    x = ((x << 4) | (x >> 4)) & 0xFF        # 니블 스왑
    x = (x * 3 - 0x2F) & 0xFF
    x = ((x << 1) | (x >> 7)) & 0xFF        # rol 1
    x ^= 0xD4
    r = 0                                   # 8비트 비트 리버스
    for _ in range(8):
        r = ((r << 1) | (x & 1)) & 0xFF
        x >>= 1
    return r


def parse(path):
    """함수별 (기대 상수, 다음 함수) 추출."""
    dis = subprocess.run(['objdump', '-d', '--no-show-raw-insn', path],
                         capture_output=True, text=True).stdout
    funcs, cur = {}, None
    for line in dis.splitlines():
        m = re.match(r'^[0-9a-f]+ <(.+)>:$', line)
        if m:
            cur = m.group(1)
            funcs[cur] = []
        elif cur is not None:
            funcs[cur].append(line)

    out = {}
    for name, body in funcs.items():
        if name != 'main' and not name.startswith('verify_func_'):
            continue
        text = '\n'.join(body)
        cmps = re.findall(r'cmp\s+\$0x([0-9a-f]+),%al', text)
        calls = [c for c in re.findall(r'call\s+[0-9a-f]+ <([^>+]+)>', text)
                 if c == 'main' or c.startswith('verify_func_')]
        assert len(cmps) == 1 and len(calls) == 1, (name, cmps, calls)
        out[name] = (int(cmps[0], 16), calls[0])
    return out


def main():
    funcs = parse(sys.argv[1] if len(sys.argv) > 1 else BIN)

    order, consts, cur = [], [], ENTRY
    for _ in range(64):                     # counter > 0x3f 에서 체인이 멈춘다
        const, nxt = funcs[cur]
        order.append(cur)
        consts.append(const)
        cur = nxt
    assert len(set(order)) == 64, 'chain is not a simple path'

    table = {calculate(c): c for c in range(256)}
    assert len(table) == 256, 'calculate not injective'

    flag = bytes(table[c] for c in consts).decode()
    print('[*] chain :', ' -> '.join(order[:4]), '-> ... ->', order[-1])
    print('[*] main is index', order.index('main'))
    print('[*] flag  : DH{%s}' % flag)

    out = subprocess.run([BIN, flag], capture_output=True, text=True).stdout
    print('[*] verify:', out.strip())
    return flag


if __name__ == '__main__':
    main()
