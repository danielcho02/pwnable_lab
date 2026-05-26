# 📄 Double DES Write-up

## 🧠 Concept: Modern Cryptography

현대 암호는 데이터를 안전하게 보호하기 위해 암호화와 복호화 과정을 사용하는 기술이다.  
암호 시스템은 크게 대칭키 암호와 공개키 암호로 나눌 수 있다.

### Symmetric Key Cryptosystem

대칭키 암호 시스템은 송신자와 수신자가 같은 키를 공유하여 암호화와 복호화를 수행하는 방식이다.

```text
암호화: Plaintext + Key → Ciphertext
복호화: Ciphertext + Same Key → Plaintext
```

대표적인 예시는 DES, AES가 있다.  
속도가 빠르다는 장점이 있지만, 송신자와 수신자가 같은 키를 안전하게 공유해야 한다는 문제가 있다.

### Asymmetric Key Cryptosystem

공개키 암호 시스템은 암호화와 복호화에 서로 다른 키를 사용하는 방식이다.  
일반적으로 공개키로 암호화하고, 개인키로 복호화한다.

```text
암호화: Plaintext + Public Key → Ciphertext
복호화: Ciphertext + Private Key → Plaintext
```

대칭키 암호보다 속도는 느리지만, 키 공유 문제를 해결할 수 있다.  
Diffie-Hellman 키 교환은 공개된 통신 환경에서도 안전하게 공통 비밀값을 만들 수 있다는 아이디어를 제공했다.

---

## 📌 Important Properties

### Confusion

혼돈은 암호문을 보고 원래 평문이나 키를 쉽게 추측하지 못하게 만드는 성질이다.  
즉, 암호문과 키 사이의 관계를 복잡하게 만든다.

### Diffusion

확산은 평문의 작은 변화가 암호문 전체에 큰 변화로 퍼지도록 만드는 성질이다.  
예를 들어 평문 1비트만 바뀌어도 암호문이 크게 달라져야 한다.

---

## 📌 Block Cipher and Stream Cipher

### Block Cipher

블록 암호는 평문을 일정한 크기의 블록으로 나누어 각 블록을 암호화하는 방식이다.

```text
Plaintext Block → Encryption → Ciphertext Block
```

DES는 64-bit, 즉 8-byte 단위 블록을 사용하는 블록 암호이다.

### Stream Cipher

스트림 암호는 키 스트림을 생성한 뒤, 평문과 결합하여 암호문을 만드는 방식이다.  
일반적으로 속도가 빠르고 구현이 가벼워 제한된 환경에서 사용되기도 한다.

---

## 📌 Four Goals of Modern Cryptography

| 기능 | 설명 |
|---|---|
| Confidentiality | 허가되지 않은 사용자가 내용을 볼 수 없게 함 |
| Integrity | 데이터가 변조되지 않았음을 보장 |
| Authentication | 통신 상대가 진짜인지 확인 |
| Non-repudiation | 나중에 행위를 부인하지 못하게 함 |

---

# 1. prob.py Analysis

## Source Code

```python
#!/usr/bin/env python3
from Crypto.Cipher import DES
import signal
import os

if __name__ == "__main__":
    signal.alarm(15)

    with open("flag", "rb") as f:
        flag = f.read()
    
    key = b'Dream_' + os.urandom(4) + b'Hacker'
    key1 = key[:8]
    key2 = key[8:]

    print("4-byte Brute-forcing is easy. But can you do it in 15 seconds?")

    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)

    encrypt = lambda x: cipher2.encrypt(cipher1.encrypt(x))
    decrypt = lambda x: cipher1.decrypt(cipher2.decrypt(x))

    print(f"Hint for you :> {encrypt(b'DreamHack_blocks').hex()}")

    msg = bytes.fromhex(input("Send your encrypted message(hex) > "))

    if decrypt(msg) == b'give_me_the_flag':
        print(flag)
    else:
        print("Nope!")
```
signal.alarm(15)를 이용해 15초의 제한 시간이 있다.   
`os.urandom` 함수를 사용하였는데 이는 값을 예측하기 굉장히 어렵다.    
따라서 앞으로도 문제에 `os.urandom`함수가 등장한다면 아무런 관련 정보 없이는 그 값을 예측하는 것은 불가능하다는 것을 전제로 두자.    

key는 총 Dream_xxxx_Hacker로 key1과 key2 모두 8바이트이며 각각 2바이트의 random값을 가진다.
```python
    key = b'Dream_' + os.urandom(4) + b'Hacker'
    key1 = key[:8]
    key2 = key[8:]
```   

`DES.new(key1, DES.MODE_ECB)`를 이용하여 `ciper1` 암호를 생성한다.
DES는 대칭키 암호이므로 키를 알면 암호화와 복호화가 모두 가능하다.    
따라서 xxxx로 표현된 random 값을 알면 된다.
`print(f"Hint for you :> {encrypt(b'DreamHack_blocks').hex()}")`에서 'DreamHack_blocks'를 암호화한 결과가 힌트로 주어지므로 이를 이용해서 key를 복구하면 될 것 같다.

## 2. Exploit by Exhuasitve search
4바이트 = 32비트 이므로 2^32의 경우의 수가 존재한다.
그 키를 모두 대입해 보았을 때 `b'DreamHack_blocks`를 암호화한 결과가 일치하면 올바른 키로 추측할 수 있으므로 전수조사(Exhaustive search)를 진행한다.
```python
from pwn import *
from Crypto.Cipher import DES
from tqdm import trange

io = process(["python3", "prob.py"])
io.recvuntil((b"Hint for you :> "))
hint = bytes.fromhex(io.recvline().strip().decode())
print(f"Hint :> {hint.hex()}")

for i in trange(0, 2**32):
    key = b'Dream_' + i.to_bytes(4, "big") + b'Hacker'
    key1 = key[:8]
    key2 = key[8:]
    cipher1 = DES.new(key1, DES.MODE_ECB)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    encrypt = lambda x: cipher2.encrypt(cipher1.encrypt(x))
    if encrypt(b'DreamHack_blocks') == hint:
        print(f"Found keys :> {key1.hex()} {key2.hex()}")
        break
```
하지만 이 방법은 시간이 너무 오래 걸려 15초안에 계산이 불가능할 뿐만 아니라 슈퍼컴퓨터의 경우에 실제로 전수조사가 가능하므로 이는 암호체계를 위협할 수 있다.
따라서 DES 암호는 사용하지 않고 있으며 현대 기술로는 2^128회의 연산이 불가능하므로 16바이트 키를 가지는 AES 대칭키는 전수 조사를 이용한 공격이 어렵다.

따라서 다른 방법을 사용해야한다.

## 3. Exploit by Meet-in-the-Middle Attack
우리가 알고 있는 식은 `cipher2.encrypt(cipher1.encrypt(b'DreamHack_blocks')) == hint`이다.
그리고 올바른 key에 대해서 A가 평문, B가 암호문일 때 `cipher2.encrypt(cipher1.encrypt(A)) == B`를 만족한다.
```   
평문 A
↓ key1로 DES 암호화
중간값
↓ key2로 DES 암호화
최종 암호문 B
```
이므로 양변에 `ciper2.decrypt`를 취해주면 `cipher1.encrypt(A) == cipher2.decrypt(B)`를 만족한다.
```
key1 후보로 평문 A를 암호화한다.
key2 후보로 암호문 B를 복호화한다.
두 결과가 같은 중간값이면 key1, key2 후보가 맞다.
```
따라서 `cipher1.encrypt(b"DreamHack_blocks") == cipher2.decrypt(hint)`를 구현하고 공통된 key를 찾는다.

최종 exploit 코드는 다음과 같다.

```python
from pwn import *
from Crypto.Cipher import DES
from tqdm import trange

io = remote("host8.dreamhack.games", 8234)
io.recvuntil(b"Hint for you :> ")
hint = bytes.fromhex(io.recvline().strip().decode())
print(f"Hint :> {hint.hex()}")

plain = b"DreamHack_blocks"

table = {}

for i in trange(2**16):
    key1 = b"Dream_" + i.to_bytes(2, "big")
    cipher1 = DES.new(key1, DES.MODE_ECB)
    mid = cipher1.encrypt(plain)
    table[mid] = key1

found_key1 = None
found_key2 = None

for j in trange(2**16):
    key2 = j.to_bytes(2, "big") + b"Hacker"
    cipher2 = DES.new(key2, DES.MODE_ECB)
    mid = cipher2.decrypt(hint)

    if mid in table:
        found_key1 = table[mid]
        found_key2 = key2
        print(f"Found key1: {found_key1}")
        print(f"Found key2: {found_key2}")
        break

cipher1 = DES.new(found_key1, DES.MODE_ECB)
cipher2 = DES.new(found_key2, DES.MODE_ECB)

target = b"give_me_the_flag"
msg = cipher2.encrypt(cipher1.encrypt(target))

io.sendlineafter(b"Send your encrypted message(hex) > ", msg.hex().encode())
io.interactive()
```
