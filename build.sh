#!/bin/bash

echo "Cleaning up build env"
#Remove bin files
echo "Removing Doxygen documentation"
rm -rf html/; rm -rf latex/
echo "Compiling source code...."
cd source_code
make main
cd -
echo "Generating doxygen documentation"
doxygen Doxyfile > /dev/null 2>&1
echo "Completed doxygen documentation"
