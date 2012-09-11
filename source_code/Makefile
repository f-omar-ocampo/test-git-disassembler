# Makefile for disassembler proyect
# Author: Ocampo Coronado Francisco Omar A00354312

CC=gcc
CFLGAS=-I

#all: disassembler.c

main: disassembler.c
	$(CC)  disassembler.c  -l elf -o disassembler -lpthread -ggdb  -l bsd

elf_h: elf_header_table.c
	$(CC)  elf_header_table.c  -l elf -o elf_header_table -lpthread -ggdb  -l bsd		

#disassembler: 

