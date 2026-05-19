# ✏️ randzzz Write-up   

## 1. 문제 접근   
IDA로 main함수를 분석하면 다음과 같다.   
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD v4[3]; // [rsp+0h] [rbp-A0h]
  _QWORD v5[3]; // [rsp+18h] [rbp-88h] BYREF
  _QWORD v6[3]; // [rsp+30h] [rbp-70h]
  int v7; // [rsp+48h] [rbp-58h]
  char v8[68]; // [rsp+50h] [rbp-50h] BYREF
  unsigned int seconds; // [rsp+94h] [rbp-Ch] BYREF
  int j; // [rsp+98h] [rbp-8h]
  int i; // [rsp+9Ch] [rbp-4h]

  puts("----Start----");
  sleep(1u);
  puts("fall asleep from now on.");
  seconds = rand() + 1;
  sleep(seconds);
  rand();
  rand();
  printf("Can you guess the rand num?: ");
  __isoc99_scanf("%d", &seconds);
  if ( rand() % 10 == seconds )
  {
    v6[0] = 0x386C2C39364C396CLL;
    v6[1] = 0x30383338AC4C4C39LL;
    v6[2] = 0x353330354CCCCC34LL;
    v7 = -865323092;
    for ( i = 0; i <= 27; ++i )
      v8[i] = get_flag(*((char *)v6 + i), seconds);
  }
  if ( rand() % 10 == seconds )
  {
    v4[0] = 0x1B323838330B1335LL;
    v4[1] = 0xB332323361B2333LL;
    v4[2] = 0x23391B0B38370B13LL;
    qmemcpy(v5, "3539458369+8", 12);
    for ( j = 0; j <= 35; ++j )
      v8[j + 28] = get_flag(*((char *)v4 + j), seconds);
  }
  printf("DH{%s}", v8);
  return 0;
}
```

if문을 확인하면 ```rand() % 10 == seconds```의 조건을 만족하면 v8에 get_flag() 함수를 이용하여 flag를 저장하고 있음을 확인할 수 있다.   

## 2. main함수 분석   
크게 두 개의 조건문이 있는데 첫 번째 조건문에서는 `v6`배열에 저장된 값을 이용하여 flag의 앞부분을 v8에 저장하고, 두 번째 조건문에서는 v4, v5에 저장된 값을 이용해 flag의 뒷 부분을 만든다.

## 3. get_flag() 함수 분석
그렇다면 `get_flag()`함수를 분석해보자.   
```c
__int64 __fastcall get_flag(unsigned int a1, char a2)
{
  signed int v3; // [rsp+10h] [rbp-10h]
  signed int v4; // [rsp+1Ch] [rbp-4h]

  if ( ((*__ctype_b_loc())[a1] & 0x800) != 0 )
  {
    v4 = 8 * a1 % '\n';
    if ( v4 <= 7 || v4 > 9 )
      return (unsigned int)(v4 + 50);
    else
      return (unsigned int)(v4 + 40);
  }
  else
  {
    v3 = (a1 << (8 - a2)) | (a1 >> a2);
    if ( v3 >= 0 )
      return (unsigned int)v3;
    else
      return (unsigned int)(v3 + 104);
  }
}
```   
main()의 첫 번째 get_flag()함수 호출을 보면
```c
v8[i] = get_flag(*((char *)v6 + i), seconds);
```
첫 번째 parameter `a1`에는 `v6` 두 번째 조건문에서는 `v4, v5`에 저장된 한 바이트 값이 들어가고 두 번쨰 parameter `a2`에는 사용자가 입력한 `seconds`값이 들어간다. 
따라서 `seconds`는 flag 문자를 만드는 key처럼 사용된다고 볼 수 있다.

```if ( ((*__ctype_b_loc())[a1] & 0x800) != 0 )```에서 `__ctype_b_loc()`는 문자의 종류를 확인할 때 사용하는 함수로, `a1`이 숫자인지 확인하는 역할을 한다.
즉, ```if(isdigit(a1))```와 같은 역할을 하고 숫자와 문자를 다르게 처리한다.
먼저 숫자인 경우 `'\n' = 10`이므로 ```v4 = (8 * a1) % 10;```를 수행 한 다음, v4의 값에 따라 50 또는 40을 더해서 ASCII값을 이용한 새로운 문자로 변환한다.
반대로 숫자가 아닌 경우에는 ```v3 = (a1 << (8 - a2)) | (a1 >> a2);```를 수행하며 단순한 shift연산처럼 보이지만 구조를 보면 8비트 기준 오른쪽 rotate연산과 비슷하다.
다시 말해 ```a1 >> a2```는 `a1`의 비트를 오른쪽으로 `a2`칸 이동시키고, `a1 << (8 - a2)`는 오른쪽으로 밀려나간 비트를 다시 왼쪽에 붙이는 역할을 한다.
그리고 두 값을 `|` 연산으로 합쳐서 최종 문자 값을 만든다.
예를 들어, `a1 = 10110010, a2 = 3`이라고 하면
```
a1 >> 3 = 00010110
a1 << 5 = 01000000
OR outcome = 01010110
```

## 4. rand() 호출 순서 분석
이제 `get_flag()`의 두 번째 parameter인 `seconds`값이 flag 복원에 사용되는 것을 알았으므로, `seconds`가 어떤 값이 되어야되는지 리버싱한다.
`main()`에서 ```rand() % 10 == seconds```의 조건을 만족해야하므로 `rand()`함수의 호출을 확인하면 사용자의 입력을 받기 전에도 
```c
seconds = rand() + 1;
sleep(seconds);
rand();
rand();
printf("Can you guess the rand num?: ");
__isoc99_scanf("%d", &seconds);
```
부분에서 여러번 호출 되고 있음을 확인할 수 있다.
따라서 `rand()`의 호출 순서는 다음과 같다.   

| 순서       | 코드 위치                  | 역할          |
| -------- | ---------------------- | ----------- |
| 1번째 rand | `seconds = rand() + 1` | sleep 시간 결정 |
| 2번째 rand | `rand();`              | 버려지는 값      |
| 3번째 rand | `rand();`              | 버려지는 값      |
| 4번째 rand | 첫 번째 if문               | flag 앞부분 조건 |
| 5번째 rand | 두 번째 if문               | flag 뒷부분 조건 |   

여기서 주목해야하는 점은 프로그램에서 `srand()`를 호출하지 않고 `rand()`만 사용한다는 것이다.
즉, `rand()`의 seed가 따로 설정되지 않았으므로 같은 환경에서는 항상 같은 순서의 난수가 return된다.

## 5. rand()의 실제 반환 순서 개념
따라서 `rand()`의 실제 반환 순서를 확인하면 된다.   
C의 `rand()`는 seed를 기준으로 pseudo-random 값을 생성한다.   
이때 같은 seed를 사용하면 항상 같은 순서의 값이 반환된다.   

이 바이너리에서는 `srand()`가 호출되지 않으므로 기본 seed가 사용된다.   
즉, `rand()`의 결과는 실행할 때마다 완전히 새롭게 바뀌는 것이 아니라, 정해진 순서대로 나온다.   

glibc 환경에서 기본 seed 기준 `rand() % 10` 값을 확인하면 다음과 같다.

| 순서 | `rand() % 10` |
|---|---|
| 1번째 | 3 |
| 2번째 | 6 |
| 3번째 | 7 |
| 4번째 | 5 |
| 5번째 | 3 |

앞에서 정리한 호출 순서에 따르면 첫 번째 if문에서 사용되는 값은 4번째 `rand() % 10`이고, 두 번째 if문에서 사용되는 값은 5번째 `rand() % 10`이다.   

따라서 첫 번째 if문의 조건을 만족하는 `seconds` 값은 `5`, 두 번째 if문의 조건을 만족하는 `seconds` 값은 `3`이다.   

하지만 사용자가 입력 할 수 있는 `seconds`값은 하나 뿐이고 첫 번째 if문을 통과하려면 `seconds == 5` , 두 번째 if문을 통과하려면 `seconds=3`이어야 한다.

## 6. solve 코드 작성
```python
import struct

def get_flag(a1, a2):
    if chr(a1).isdigit():
        v4 = (8 * a1) % 10
        if v4 <= 7 or v4 > 9:
            return (v4 + 50) & 0xff
        else:
            return (v4 + 40) & 0xff
    else:
        v3 = ((a1 << (8 - a2)) | (a1 >> a2))
        return v3 & 0xff

v6 = struct.pack("<QQQi",
    0x386C2C39364C396C,
    0x30383338AC4C4C39,
    0x353330354CCCCC34,
    -865323092
)

v4 = struct.pack("<QQQ",
    0x1B323838330B1335,
    0x0B332323361B2333,
    0x23391B0B38370B13
) + b"3539458369+8"

part1 = bytes(get_flag(c, 5) for c in v6)
part2 = bytes(get_flag(c, 3) for c in v4)

print(b"DH{" + part1 + part2 + b"}")
```
앞에서 분석한 내용을 바탕으로 `get_flag()`함수를 python으로 구현한다.
ida에서 디컴파일 했을 때 값들은 문자열이 아니라 메모리에 저장된 정수 값이고 x86-64 환경에서는 little endian 방식으로 값이 저장되므로, python에서 실제 메모리의 바이트 순서로 복원하기 위해서 `struct.pack("<Q", value)` 형태를 사용했다.
`<` 는 little endian을 의미하고, `Q`는 8byte unsigned long long, `i`는 4byte int를 의미한다.
`v6`은 `_QWORD` 3개와 `int v7`이 연속해서 사용되므로 `"<QQQi"`로 붂어 복원했다.   
두 번째 flag 조각에 사용되는 값은 `v4`와 `v5`에 나누어 저장되어 있다.
```python
v4 = struct.pack("<QQQ",
    0x1B323838330B1335,
    0x0B332323361B2333,
    0x23391B0B38370B13
) + b"3539458369+8"
```
앞서 `rand()` 호출 순서를 분석한 결과 첫 번째 if문은 `second == 5`, 두 번쨰 if문은 `second == 3`이어야 하므로 
```python
part1 = bytes(get_flag(c, 5) for c in v6)
part2 = bytes(get_flag(c, 3) for c in v4)

print(b"DH{" + part1 + part2 + b"}")
```
을 이용해 flag를 각각 복원한 뒤 합치면
```bash
b'DH{c8b48ac08bbe00068ffb6606e2cf6ba0002c0dc4dd0aba20ac8d0608860048e0}'
```
flag를 구할 수 있다.
