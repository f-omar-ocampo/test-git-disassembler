*************************************************************************
*	OCAMPO CORONADO FRANCISCO OMAR A00354312			*
*									*
*	DISASSEMBLER	                         			*
*									*
*************************************************************************

1.- Build pre-requisites
    ***Note: Only ubuntu is suported for this release***

    A) Install build-essentials software
       user_prompt> sudo apt-get install build-essential
    
    B) Install libelf library (latest version)

	user_prompt> wget http://ftp.br.debian.org/debian/pool/main/e/elfutils/libelf-dev_0.153-1_i386.deb
	user_prompt> wget http://ftp.br.debian.org/debian/pool/main/e/elfutils/libelf1_0.153-1_i386.deb
	user_prompt> sudo dpkg -i libelf-dev_0.153-1_i386.deb libelf1_0.153-1_i386.deb
	user_prompt> cd /usr/lib/x86_64-linux-gnu/
	user_prompt> ln -s libelf.a /usr/lib/libelf.so
	user_prompt> sudo ln -s libelf.a /usr/lib/libelf.so
	user_prompt> sudo ln -s libelf.a /usr/lib32/libelf.so

	Make sure to create a symbolic link of libelf to /usr/lib and /usr/lib32 and /usr/lib64

    C) Execute ldconfig
	user_prompt> ldconfig

    D) Install libbsd-dev
        user_prompt> sudo apt-get install libbsd-dev

    E) Install Doxygen
        user_prompt > sudo apt-get install doxygen

2.- How to build
    Run build.sh script, executable(s) will be created, test will run and documentation will be created.
	
3.- Documentation
    Documentation can be found under docs directory. Documentation generated by Doxygen

4.- Running tests
    Use google tests to run the tests
    
    user_prompt> tests/disassembler_tests_feature --gtest_filter=TC_DA_GenInst

    **Note: For a complete list of tests, please check tests/Test_plan.txt

5.- Running disassembler
    
    Disassembler can use used with this options:

    -f --file: Provide the file to disassemble
    -o --opcode: Get information of a single opcode (Cannot be used with -f option)
    -n --noelf: Do not show elf information (Default: show ON)

6.- Creadits
    Google, Intel manuals, MazeGen XML, pugixml creator, libelf creators, anonymous people in stackoverflow.

	And you!

	FIN



