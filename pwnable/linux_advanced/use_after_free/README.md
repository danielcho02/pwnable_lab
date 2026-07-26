# 🧠 Use-After-Free(UAF)

## 📌 Definition
Memory Allocator = 한정된 메모리 자원을 각 프로세스에 효율적으로 배분   
모든 프로세스는 실행 중에 메모리를 동적으로 할당 → 해제   
Use-After-Free = 메모리 참조에 사용한 포인터를 메모리 해제 후에 적절히 초기화하지 않아서 or 해제한 메모리를 초기화하지 않고 다음 청크에 재할당해주면서 발생하는 취약점
브라우저 및 커널에서 자주 발견됨

---

## 📄 ptmalloc2 (ptherad malloc 2)
메모리의 효율적인 관리 - 메모리 낭비 방지, 빠른 메모리 재사용, (내.외부)메모리 단편화 방지 

### 1. 청크(Chunk) 
ptmalloc이 할당한 메모리 공간   
header + data   
![ptmalloc 청크 구조](https://dreamhack-lecture.s3.amazonaws.com/media/4b0c74248164c0b89c3c47d2beed97fd3b22a268520eb070b8c613e70b0d2fb9.png)

| 이름 | 크기 | 의미 |
|---|:---:|---|
| `prev_size` | 8&#8288;바&#8288;이&#8288;트 | 인접한 직전 청크의 크기. 청크를 병합할 때 직전 청크를 찾는 데 사용됩니다. |
| `size` | 8&#8288;바&#8288;이&#8288;트 | 현재 청크의 크기. 헤더의 크기도 포함한 값입니다. 64비트 환경에서 사용 중인 청크 헤더의 크기는 16바이트이므로, 사용자가 요청한 크기를 정렬하고 그 값에 16바이트를 더한 값이 됩니다. |
| `flags` | 3&#8288;비&#8288;트 | 64비트 환경에서 청크는 16바이트 단위로 할당되므로, `size`의 하위 4비트는 의미를 갖지 않습니다. 그래서 ptmalloc은 `size`의 하위 3비트를 청크 관리에 필요한 플래그 값으로 사용합니다.<br><br>각 플래그는 순서대로 allocated arena(`A`), mmap'd(`M`), prev-in-use(`P`)를 나타냅니다. `prev-in-use` 플래그는 직전 청크가 사용 중인지를 나타내므로, ptmalloc은 이 플래그를 참조하여 병합이 필요한지 판단할 수 있습니다. 나머지 플래그에 대해서는 여기서 설명하지 않겠습니다. |
| `fd` | 8&#8288;바&#8288;이&#8288;트 | 연결 리스트에서 다음 청크를 가리킵니다. **해제된 청크에만 있습니다.** |
| `bk` | 8&#8288;바&#8288;이&#8288;트 | 연결 리스트에서 이전 청크를 가리킵니다. **해제된 청크에만 있습니다.** |

청크를 관리하는 방법   
Fragmentation - LIFO < FIFO < address-orderd
속도는 반대

### 2. bin
사용이 끝난 청크들을 저장
메모리 낭비를 막고 해제된 청크를 빠르게 재사용할 수 있음   
128 bins = 62 smallbin + 63 largebin + 1 unsortedbin + 2 not-used   
- smallbin: 32바이트 이상 1024 바이트 미만 크기를 갖는 청크 보관, circular doubly-linked list
- fastbin: 32바이트 이상 128바이트 이하의 청크 저장(Linux), 단편화보다 속도 중요
- largebin: 1024 바이트 이상의 크기를 갖는 청크 보관, best-fit
- unsortedbin: 분류되지 않은 청크 보관
- arena: fastbin, smallbin, largebin 등의 정보를 모두 담고 있는 객체, 최대 64개 생성가능

### 3. tcache = thread local cache    
각 쓰레드에 독립적으로 할당되는 캐시 저장소
LIFO, 단일 연결 리스트
ptmalloc이 race condition을 고려하지 않고 접근 가능, bottleneck 완화


## 📄 UAF
### 1. Dangling Pointer
유효하지 않은 메모리 영역을 가리키는 포인터
`malloc` → `free` 이후에 포인터를 초기화하지 않으면 해제된 청크를 가리키는 Dangling Pointer가 됨

### 2. Use After Free
해제된 메모리에 접근할 수 있을 때 발생하는 취약점
새롭게 할당한 영역을 초기화하지 않고 사용하면서 발생
`malloc`, `free` 함수는 할당 or 해제할 메모리 데이터 초기화 X
→ 메모리에 남아있던 데이터가 유출되거나 사용할 수 있음
```c
// Name: uaf.c
// Compile: gcc -o uaf uaf.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct NameTag {
  char team_name[16];
  char name[32];
  void (*func)();
};

struct Secret {
  char secret_name[16];
  char secret_info[32];
  long code;
};

int main() {
  int idx;

  struct NameTag *nametag;
  struct Secret *secret;

  secret = malloc(sizeof(struct Secret));

  strcpy(secret->secret_name, "ADMIN PASSWORD");
  strcpy(secret->secret_info, "P@ssw0rd!@#");
  secret->code = 0x1337;

  free(secret);
  secret = NULL;

  nametag = malloc(sizeof(struct NameTag));

  strcpy(nametag->team_name, "security team");
  memcpy(nametag->name, "S", 1);

  printf("Team Name: %s\n", nametag->team_name);
  printf("Name: %s\n", nametag->name);

  if (nametag->func) {
    printf("Nametag function: %p\n", nametag->func);
    nametag->func();
  }
}
```
`Secret` struct를 먼저 할당하고 `secret_name`, `secret_info`, `code`에 값을 입력 후 `free(secret)`
이후 사원 정보를 담고 있는 `nametag`생성, `team_name`, `name`에 각각 값을 입력하고 출력
```bash
$ gcc -o uaf uaf.c -no-pie
$ ./uaf
Team Name: security team
Name: S@ssw0rd!@#
Nametag function: 0x1337
Segmentation fault (core dumped)
```
컴파일 후 실행하면 Name으로 `secret_info`의 문자열이 출력
`ptmalloc2`는 요청된 크기와 비슷한 청크가 `bin`이나 `tcache`에 있는지 확인하고 재사용하기 때문
`Nametag`와 `Secret`은 같은 크기의 구조체이므로 `secret`을 해제하고 `nametag`를 할당하면 같은 메모리 영역 사용

초기화되지 않은 메모리의 값을 읽어내거나, 새로운 객체가 악의적인 값을 사용하도록 유도하여 프로그램의 정상적인 실행 방해 가능

---

## 🔑 Key Takeaways

- UAF는 `free()`된 메모리를 계속 참조하면서 발생
- `malloc()`과 `free()`는 메모리 내부 데이터를 자동으로 초기화 X
- 같은 크기의 청크를 다시 할당하면 이전에 해제된 메모리 영역이 재사용 가능
- 이 과정에서 이전 데이터가 유출되거나 함수 포인터 같은 중요한 값이 잘못 사용될 가능성
- UAF를 방지하려면 `free()` 후 포인터를 `NULL`로 초기화하고, 새로 할당한 메모리도 반드시 초기화 필요!
