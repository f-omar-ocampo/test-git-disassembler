# Makefile for disassembler proyect
# Author: Ocampo Coronado Francisco Omar A00354312

CC=gcc
CFLGAS=-I

all: main gcov hello_world

#examples: 

main: disassembler.c
	$(CC)  disassembler.c  -l elf -o ../disassembler -lpthread -ggdb  -l bsd

gcov: disassembler.c
	$(CC) -fprofile-arcs -ftest-coverage disassembler.c  -l elf -o disassembler -lpthread -ggdb  -l bsd

#These are the examples to be used by disassemble
hello_world: examples_to_read/hello_world.cpp
	g++ examples_to_read/hello_world.cpp -o examples_to_read/hello

#disassembler: 

