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