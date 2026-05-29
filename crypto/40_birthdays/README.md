# 📄 40 Birthdays write-up

## 1. chall.py Analysis
Source Code
```python
import hashlib

def birthday_hash(msg):
    return hashlib.sha256(msg).digest()[12:17]

msg1 = bytes.fromhex(input("Input message 1 in hex: "))
msg2 = bytes.fromhex(input("Input message 2 in hex: "))

if msg1 == msg2:
    print("Those two messages are the same! >:(")

elif birthday_hash(msg1) != birthday_hash(msg2):
    print("Those two messages don't have the same birthday! T.T")

else:
    print("Finally! They have the same birthday ^o^")
    print(open("flag.txt").read())
```
서로 다른 두 메시지를 입력해, 같은 해시 값을 가진다면 flag를 획득할 수 있다.
`birthday_hash`는 SHA-256함수를 32byte로 나타냈을 때 중간에 존재하는 5bytes = 40bits이므로 2^40+1개 메시지의 해시값을 구하면 충돌이 무조건 발생한다.

## 2. Exploit

이 문제는 SHA-256 전체 32 bytes를 비교하는 것이 아니라, 그중 일부인 5 bytes만 비교한다.

```python
def birthday_hash(msg):
    return hashlib.sha256(msg).digest()[12:17]
```

`digest()[12:17]`은 SHA-256 결과 중 5 bytes만 잘라낸다.  
즉 비교되는 해시값의 크기는 다음과 같다.

$$
5 \text{ bytes} = 40 \text{ bits}
$$

따라서 가능한 해시값의 전체 개수는 다음과 같다.

$$
N = 2^{40}
$$

서로 다른 메시지를 계속 넣다 보면 같은 해시값을 가지는 두 메시지를 찾을 수 있다.  
단순히 충돌을 반드시 보장하려면 비둘기집 원리에 의해 `2^40 + 1`개의 메시지가 필요하다.

하지만 이 문제는 Birthday Attack을 이용할 수 있다.  
공역의 크기가 `N`인 해시 함수에서 `K`개의 서로 다른 메시지를 넣었을 때, 충돌이 발생하지 않을 확률은 대략 다음과 같다.

$$
P(\text{no collision}) \approx e^{-\frac{K(K-1)}{2N}}
$$

따라서 충돌이 발생할 확률은 다음과 같다.

$$
P(\text{collision}) \approx 1 - e^{-\frac{K(K-1)}{2N}}
$$

여기서 `N = 2^40`이고, `K = 2^21` 정도로 잡으면 다음과 같이 계산할 수 있다.

$$
\frac{K^2}{2N} = \frac{(2^{21})^2}{2 \cdot 2^{40}} = \frac{2^{42}}{2^{41}} = 2
$$

따라서 충돌 확률은 대략 다음과 같다.

$$
P(\text{collision}) \approx 1 - e^{-2}
$$

즉 약 86% 정도의 확률로 충돌을 찾을 수 있다.  
그래서 `2^40`번을 전부 브루트포싱하지 않고, 약 `2^20 ~ 2^21`번 정도의 시도로도 충분히 높은 확률로 충돌을 찾을 수 있다.

최종 exploit 코드는 다음과 같다.

```python
import hashlib
from tqdm import trange
from pwn import *

def birthday_hash(msg):
    return hashlib.sha256(msg).digest()[12:17]

hash_table = {}

for i in trange(2**21):
    msg = str(i).encode()
    result = birthday_hash(msg)

    if result in hash_table:
        msg1 = hash_table[result]
        msg2 = msg
        break

    hash_table[result] = msg

assert msg1 != msg2
assert birthday_hash(msg1) == birthday_hash(msg2)

io = remote("host3.dreamhack.games", 16793)

io.sendlineafter(b": ", msg1.hex().encode())
io.sendlineafter(b": ", msg2.hex().encode())

io.interactive()
```

코드의 핵심은 이미 나온 해시값을 `hash_table`에 저장해두는 것이다.  
새로운 메시지의 `birthday_hash` 결과가 이미 `hash_table`에 존재한다면, 서로 다른 두 메시지가 같은 5-byte 해시값을 가진다는 뜻이다.

이후 두 메시지를 hex 형식으로 서버에 보내면 다음 조건을 만족하게 된다.

```python
birthday_hash(msg1) == birthday_hash(msg2)
```

따라서 서버는 두 메시지가 같은 birthday를 가진다고 판단하고 flag를 출력한다.
