#This Makefile compiles 
 
#Subsitute this directory with Gtest installation folder.
GTEST_DIR = ./gtest-1.5.0/
 
#Define compiler and flags
CC = g++
CFLAGS = -I$(GTEST_DIR)/include/

all: feature spec

################################################################################
#			  FEATURE-TESTS
################################################################################
feature: gtest-all.o feature.cpp
	$(CC) $(CFLAGS) feature.cpp gtest-all.o -lpthread -o ./disassembler_tests_feature

################################################################################
#			  SPEC-TESTS
################################################################################
spec: gtest-all.o spec.cpp
	$(CC) $(CFLAGS) spec.cpp gtest-all.o -lpthread -o ./disassembler_tests_spec

#Compile Gtest-all functions (Google Tests library)
gtest-all.o : $(GTEST_DIR)/src/gtest-all.cc
	$(CC) $(CFLAGS) -I$(GTEST_DIR) -c $(GTEST_DIR)/src/gtest-all.cc
