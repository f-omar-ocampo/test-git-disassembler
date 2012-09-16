#!/usr/bin/python

import os
import sys
import subprocess
import logging
from optparse import OptionParser

global DA
DA = '../disassembler'


def run(cmd, silent=False):
    """Execute process and return ouput"""
    proc_stdout = ''
    if not silent:
        logging.debug("Executing:\t\t" + cmd)
    proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            )
    proc_stdout = proc.communicate()[0]
    if not silent:
        logging.debug(proc_stdout)
        print ""
    return proc_stdout.strip()


#def run_get_returncode(cmd, silent=False):

def is_binary(file_to_check):
    file_type = ''
    cmd = "file -b -e soft " + str(file_to_check)
    if os.path.exists(file_to_check):
        file_type = run(cmd)
        if 'data' in file_type:
            print "File is a binary file"
            return True
        return False
    else:
        print "File does not exists"
        return False


def TC_DA_OpenBinFile():
    global DA
    cmd = DA + " " + sys.argv[0]
    output = run(cmd)
    if 'NON binary/object file' in output:
        logging.info("Disassembler correctly ignored a python file.")
    cmd = DA + " ../disassembler"
    output = run(cmd)
    if 'Detected binary/object file' in output:
        logging.info("Disassembler correctly opened a binary/object file")
        return True
    return False


def TC_DA_SendNonExistanceFile():
    global DA
    cmd = DA + " ~/I_luvz_my_dog"
    output = run(cmd)
    if "File provided does not exists" in output:
        logging.info("Disassembler correctly catched non-existance file")
        return True
    return False


def TC_DA_PrintElf():
    global DA
    cmd = DA + " ../disassembler"
    output = run(cmd)
    if "Elf type: elf object" in output or "Elf type: ar(1) archive" in output:
        logging.info("Elf file detected")
    if "ELF HEADER" in output:
        logging.info("ELF headers printed")
        return True
    return False


def TC_DA_NoPrintElf():
    return not TC_DA_PrintElf()



def main():
    logging.basicConfig(level=logging.INFO)
    parser = OptionParser()
    parser.add_option("-t", "--test", dest="test", default='',
                      help="""Test to run""", metavar="TEST")
    (options, args) = parser.parse_args()
    test = options.test.lower()
    TC_DA_OpenBinFile()
    TC_DA_SendNonExistanceFile()

if __name__ == "__main__":
    main()

