from capstone import *
from elftools.elf.elffile import ELFFile
from collections import deque
import pprint
import os

mem_buffer = ["A"] * 256

binary = open(f"./autorev_assemble", "rb")
instructions = []
elf_file = ELFFile(binary)
dot_text = elf_file.get_section_by_name(".text")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print(elf_file.stream)
