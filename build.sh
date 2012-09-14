#!/bin/bash

echo "
*************************************************************************
*	OCAMPO CORONADO FRANCISCO OMAR A00354312			*
*									*
*	CONTINUOS INTEGRATION FOR DISASSEMBLER				*
*									*
*************************************************************************
"

echo "Generating binaries..."
cd source_code/
make all
cd -
echo "Executing testing..."
# Execute tests, including gcov
#./disassembler ./disassembler  > /dev/null
#Generate gcov 
#gcov ./disassembler.c
echo "Generating documentation..."
doxygen Doxyfile > /dev/null

