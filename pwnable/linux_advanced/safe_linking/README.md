# 🧠 Safe Linking

## 📌 Definition

`Double Free Bug`는 glibc 2.29부터 추가된 `e->key` 검증으로 1차 차단된다. tcache에 들어간 청크에는 `tcache_key` 표식이 찍히고, free 시 이 표식이 이미 있으면 이중 해제로 판단한다.

그러나 `Use After Free` 같은 취약점으로 tcache 청크의 `next` 포인터를 임의로 덮을 수 있으면, 원하는 주소를 tcache list에 끼워 넣어 임의 주소에 청크를 할당받을 수 있다.

- **Tcache Poisoning** → tcache는 다른 bin에 비해 무결성 검사가 약하고 `Singly Linked List` 구조라 `next` 조작이 곧 할당 위치 조작으로 이어진다.
- **Safe Linking** → 이 공격을 막기 위해 tcache/fastbin의 `next`에 저장되는 주소값을 인코딩/디코딩하는 기법. glibc 2.32부터 적용된다.

---

## 📄 Safe Linking 구현

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)

static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  e->key = tcache_key;                                  // DFB 탐지용 표식
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);  // next를 인코딩해서 저장
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);       // 꺼낼 때 디코딩
  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```

- `PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`
  - `pos` : `next` 필드가 **저장된 주소**
  - `ptr` : `next`에 **넣으려는 실제 포인터**
- `REVEAL_PTR`은 같은 연산을 다시 적용해 원래 값을 복원한다(XOR의 자기역원 성질).

여기서 인코딩 키 역할을 하는 `pos >> 12`는 비밀 난수가 아니라 **힙 주소의 상위 부분**이다. 이 사실이 뒤의 우회의 출발점이 된다.

---

## 📄 Safe Linking이 영향을 미치는 tcache 공격 기법

`next` 필드를 덮어 Tcache Poisoning을 하려면, 평문 주소를 쓰는 게 아니라 **`PROTECT_PTR()`을 통과한 인코딩 값**을 써야 한다. 상황은 leak 가능 여부로 갈린다.

1. **heap address leak이 가능하면** — Safe Linking은 사실상 장애물이 아니다. `pos`(next 필드 주소)를 알고 `ptr`(목적지)을 정하면 `PROTECT_PTR`을 그대로 계산해 넣으면 끝난다.
2. **leak이 없고 같은 페이지 내부만 노릴 때** — `partial overwrite` + `1/256 brute forcing`. 인코딩 값의 하위 바이트가 무작위 힙 상위 주소(`pos >> 12`)에 의존하므로, 모르는 1바이트를 찍어 확률적으로 맞힌다.

---

## 📄 Safe Linking 우회 (인코딩 값 leak → 원본 복구)

`pos >> 12`가 힙 주소라는 점 때문에, 인코딩된 `next` 값 하나만 유출해도 역연산으로 원본 주소를 되돌릴 수 있다. 다음 조건에서 성립한다.

```
1. 힙 주소가 1.5바이트(12비트) 단위로 정렬되어 상위 바이트가 공유됨
2. 공격자가 현재 청크의 인코딩된 next 값을 유출할 수 있음
3. 동적 디버깅으로, 유출된 next의 원본(ptr)과 현재 청크 주소(pos)가
   하위 1.5바이트만 다르다는 사실을 관측
```

### 인코딩 (PROTECT_PTR)

```
pos (현재 청크의 next 필드 주소) = 0xdeadbeefca00
ptr (next의 본래 값)             = 0xdeadbeefcc00   # pos와 하위 1.5바이트만 상이

PROTECT_PTR(pos, ptr)
= (0xdeadbeefca00 >> 12) ^ 0xdeadbeefcc00
= 0xdeadbeefc      ^ 0xdeadbeefcc00
= 0xdea0543422fc                                    # 실제 저장되는 인코딩 값
```

### 디코딩 (역연산 원리)

핵심은 `>> 12`가 값을 아래로 밀어내면서 **최상위 12비트 블록이 그대로 노출**된다는 점이다. 인코딩 값을 1.5바이트(12비트) 블록으로 나누면, 위 블록부터 아래로 순서대로 벗겨낼 수 있다.

유출값 `L = 0xdea0543422fc`를 12비트 블록으로 분할한다.

```
L = [ dea ][ 054 ][ 342 ][ 2fc ]     # 상위 → 하위

b3 = 0xdea                           # 최상위 블록 = ptr 상위 12비트 (그대로 노출)
b2 = 0x054 ^ b3 = 0x054 ^ 0xdea = 0xdbe
b1 = 0x342 ^ b2 = 0x342 ^ 0xdbe = 0xefc
b0 = 0x2fc ^ b1 = 0x2fc ^ 0xefc = 0xc00

ptr = [ dea ][ dbe ][ efc ][ c00 ] = 0xdeadbeefcc00   # 원본 복구 성공
```

`pos >> 12`가 힙 상위 주소이고, `pos`와 `ptr`이 상위 바이트를 공유하므로,
`L`의 각 블록은 `ptr`의 인접 상위 블록과 XOR된 형태다. 그래서 위 블록을
복구할 때마다 바로 아래 블록의 키가 드러나고, 이를 연쇄적으로 XOR로
제거하면 전체 `ptr`이 복원된다. 복원된 `ptr`은 실제 힙 주소이므로 곧
**heap leak**이 되고, Safe Linking은 무력화된다.

---

## ✅ Key Takeaways

- Safe Linking은 tcache/fastbin의 `next`를 `(pos >> 12) ^ ptr`로 인코딩해 저장하는 기법이며 **glibc 2.32+**에 적용된다.
- 인코딩 "키"인 `pos >> 12`는 난수가 아니라 **힙 주소의 상위 부분**이다. 이 구조적 약점이 모든 우회의 근거다.
- **heap leak이 있으면** `pos`를 알 수 있으므로 `PROTECT_PTR`을 직접 계산해 넣으면 되고, Safe Linking은 장애물이 되지 않는다.
- **leak이 없으면** 같은 페이지 내부를 노리는 `partial overwrite`로 좁히되, 무작위 상위 바이트 때문에 1바이트를 `1/256`로 브루트포싱해야 한다.
- **인코딩 값 하나만 유출**되어도, 상위 12비트 블록부터 아래로 XOR를 벗겨내는 역연산으로 원본 주소를 복구할 수 있다(상위 바이트 공유가 전제).
- `e->key` 검증(DFB 탐지)과 Safe Linking(`next` 무결성)은 **서로 다른 보호기법**이다. DFB 우회는 `key`를 지우는 것, Safe Linking 우회는 `next`를 올바르게 인코딩하는 것으로 목적이 나뉜다.
