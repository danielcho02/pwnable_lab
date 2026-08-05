# ✏️ Testify
https://dreamhack.io/wargame/challenges/622

## 📄 Vulnerability & Code Analysis

이 문제는 입력한 문자열이 직접 flag인지 검사하는 구조가 아니라, 사용자가 넣은 문자열 패턴이 내부의 숨겨진 문자열 안에 존재하는지 검사하는 구조이다.

프로그램 실행 흐름은 다음과 같다.

```text
amount 입력
    ↓
input 1, input 2, ... 패턴 입력
    ↓
입력 패턴들로 trie 형태의 검색 구조 생성
    ↓
내부 문자열을 한 글자씩 순회
    ↓
입력 패턴 중 하나라도 내부 문자열에 등장하면 pure!
등장하지 않으면 fail...
```

로컬 바이너리에서 `strings`를 확인하면 다음 힌트가 존재한다.

```text
real flag is [0-9a-f]{64}. Have a nice day!
```

따라서 실제 원격 서버의 숨겨진 값은 `0-9`, `a-f`로 이루어진 64자리 hex 문자열이라고 추정할 수 있다.

실제로 로컬에서 다음 입력은 `pure!`가 출력된다.

```text
real
flag
Have
```

반면 다음 입력은 `fail...`이 출력된다.

```text
DH{
0000
ac
```

즉 `pure!`는 “정답을 맞혔다”가 아니라, 내가 넣은 문자열이 내부 target 문자열의 부분 문자열이라는 뜻이다.

또한 `generate_testify` 함수 내부에서 입력을 받을 때 다음과 같은 구조가 확인된다.

```c
read(0, buf, 0x10);
```

즉 한 번에 질의할 수 있는 문자열 길이는 최대 16바이트이다.  
따라서 17바이트 이상의 문자열을 보내면 나머지 바이트가 stdin에 남아 다음 입출력이 꼬일 수 있다.

---

## 🗡️ Exploit / Solver Strategy

이 문제의 핵심은 `pure! / fail...` 출력을 오라클로 사용하는 것이다.

```text
pure!  → 입력한 pattern이 숨겨진 flag 안에 존재함
fail   → 입력한 pattern이 숨겨진 flag 안에 존재하지 않음
```

쉽게 말하면 숫자야구나 스무고개처럼, 프로그램에게 문자열 조각을 계속 물어보면서 숨겨진 64자리 hex flag를 복원하는 방식이다.

먼저 hex 문자셋을 기준으로 질의한다.

```python
ALPH = b"0123456789abcdef"
```

초기 solver로 부분 문자열을 확장한 결과, 다음 16바이트 substring을 찾을 수 있었다.

```text
d6371f1cfc993067
```

하지만 프로그램은 입력 하나당 최대 16바이트만 읽으므로, 이보다 긴 문자열을 직접 물어볼 수 없다.

따라서 16바이트 sliding window 방식으로 flag를 복원한다.

예를 들어 현재 찾은 조각이 다음과 같다고 하자.

```text
d6371f1cfc993067
```

오른쪽 한 글자를 더 찾고 싶을 때 17글자인 다음 문자열을 직접 질의하면 안 된다.

```text
d6371f1cfc993067?
```

대신 맨 앞 한 글자를 버리고 마지막 15글자에 후보 문자 하나를 붙여 16바이트만 질의한다.

```text
6371f1cfc9930670
6371f1cfc9930671
6371f1cfc9930672
...
6371f1cfc993067f
```

이 중 `pure!`가 뜨는 후보가 실제 다음 window가 된다.  
같은 방식으로 오른쪽 확장이 막히면 왼쪽도 확인하면서 전체 길이가 64가 될 때까지 반복한다.

---

## 💻 Final Payload or Solver

```python
from pwn import *
import json
import os
import time

context.log_level = "error"

LOCAL = False
BIN = "./chal"

HOST = "host3.dreamhack.games"
PORT = 9740

ALPH = b"0123456789abcdef"
K = 16
TARGET_LEN = 64

SEED = b"d6371f1cfc993067"

CACHE_FILE = "oracle_cache.json"


class Oracle:
    def __init__(self):
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                self.cache = json.load(f)
        else:
            self.cache = {}

        self.query_count = 0

    def save(self):
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f, indent=2, sort_keys=True)

    def start(self):
        if LOCAL:
            return process(BIN)
        return remote(HOST, PORT)

    def ask(self, pattern: bytes) -> bool:
        assert 1 <= len(pattern) <= K, f"bad query length: {len(pattern)} {pattern!r}"

        key = pattern.decode()

        if key in self.cache:
            return self.cache[key]

        for attempt in range(5):
            p = None
            try:
                p = self.start()

                p.recvuntil(b"amount:", timeout=5)
                p.sendline(b"1")

                p.recvuntil(b"input 1:", timeout=5)
                p.sendline(pattern)

                out = p.recvuntil(b"Try Again?", timeout=5)

                ok = b"pure!" in out

                self.cache[key] = ok
                self.query_count += 1

                print(f"[Q {self.query_count:05d}] {pattern.decode()} -> {ok}")

                if self.query_count % 20 == 0:
                    self.save()

                p.close()
                return ok

            except EOFError:
                if p:
                    p.close()
                print(f"[!] EOF, retry {attempt + 1}/5: {pattern!r}")
                time.sleep(0.3)

            except Exception as e:
                if p:
                    p.close()
                print(f"[!] ERR {type(e).__name__}, retry {attempt + 1}/5: {pattern!r}")
                time.sleep(0.3)

        raise RuntimeError(f"oracle failed too many times: {pattern!r}")


def current_windows(s: bytes):
    return {s[i:i + K] for i in range(0, max(0, len(s) - K + 1))}


def right_candidates(s: bytes, oracle: Oracle):
    used = current_windows(s)
    suffix = s[-(K - 1):]

    cands = []
    for c in ALPH:
        q = suffix + bytes([c])
        if q in used:
            continue
        if oracle.ask(q):
            cands.append(bytes([c]))

    return cands


def left_candidates(s: bytes, oracle: Oracle):
    used = current_windows(s)
    prefix = s[:K - 1]

    cands = []
    for c in ALPH:
        q = bytes([c]) + prefix
        if q in used:
            continue
        if oracle.ask(q):
            cands.append(bytes([c]))

    return cands


def solve_greedy():
    oracle = Oracle()
    s = SEED

    print(f"[+] seed len={len(s)} {s.decode()}")

    while len(s) < TARGET_LEN:
        progressed = False

        while len(s) < TARGET_LEN:
            cands = right_candidates(s, oracle)

            if not cands:
                print("[*] no right candidate")
                break

            if len(cands) > 1:
                print(f"[!] right branch at {s.decode()} -> {[c.decode() for c in cands]}")

            c = cands[0]
            s += c
            progressed = True
            print(f"[R] len={len(s):02d} {s.decode()}")

        if len(s) >= TARGET_LEN:
            break

        while len(s) < TARGET_LEN:
            cands = left_candidates(s, oracle)

            if not cands:
                print("[*] no left candidate")
                break

            if len(cands) > 1:
                print(f"[!] left branch at {s.decode()} -> {[c.decode() for c in cands]}")

            c = cands[0]
            s = c + s
            progressed = True
            print(f"[L] len={len(s):02d} {s.decode()}")

        if not progressed:
            print("[-] stuck")
            break

    oracle.save()

    print("=" * 80)
    print(f"[+] result len={len(s)}")
    print(s.decode())

    if len(s) == TARGET_LEN:
        print("[+] submit this value")
    else:
        print("[-] not complete yet")


if __name__ == "__main__":
    solve_greedy()
```

---

## 🏳️ cat flag

Solver를 실행하면 `pure! / fail...` 응답을 이용해 64자리 hex 문자열을 복원할 수 있다.

```text
[+] seed len=16 d6371f1cfc993067
...
[+] result len=64
<recovered_64_hex_flag>
[+] submit this value
```

