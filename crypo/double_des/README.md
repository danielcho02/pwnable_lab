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

