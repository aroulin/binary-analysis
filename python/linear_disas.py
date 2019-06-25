#!/usr/bin/python2.7

import argparse

import pefile
from capstone import *

args = argparse.ArgumentParser(
    description="Perform linear disassembly on a binary (first 100 bytes only)\n"
)

args.add_argument("binary", help="binary to disassemble")
args = args.parse_args()

pe = pefile.PE(args.binary)

entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
entrypoint_address = entrypoint + pe.OPTIONAL_HEADER.ImageBase

binary_code = pe.get_memory_mapped_image()[entrypoint:entrypoint + 100]

disassembler = Cs(CS_ARCH_X86, CS_MODE_64)

print "Sections:\n"
for section in pe.sections:
    print (section.Name, hex(section.VirtualAddress),
           hex(section.Misc_VirtualSize), section.SizeOfRawData)

print "DLL Imports:\n"
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print entry.dll
    for function in entry.imports:
        print '\t', function.name
print"\n\n"

print "First 100 bytes of instructions"
for instruction in disassembler.disasm(binary_code, entrypoint_address):
    print "%s\t%s" % (instruction.mnemonic, instruction.op_str)
