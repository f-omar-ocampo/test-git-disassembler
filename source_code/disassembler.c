#include <bsd/vis.h>
#include <typeinfo>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <gelf.h>
#include <libelf.h>
#include "pugixml/pugixml.cpp"
#include <sysexits.h>
#include <unistd.h>

using namespace std;
using namespace pugi;

FILE* open_file(char *file_name, const char *mode);
void is_binary(string file);
unsigned long get_file_size(char *file_name);
void file_size_limits(unsigned long kb);

void print_binary_file(char *file_name, unsigned long file_size);
void print_binary_file_hex(char *file_name, unsigned long file_size);

void elf_check_up(char *file_name);
void read_file_type_elf(char *file_name);
void read_elf_exe_header(char *file_name);
void print_ptype(size_t pt);
void read_elf_program_header(char *file_name);

struct Opcode_info
{
    /*
     * Possible elements of an opcode
     * All the information will be get from the XML
     * Some parameters may be in blank because opcodes does not have such
     * element on it.
     */
    struct entry_attributes
    {
        string direction;
        string op_size;
        string r;
        string lock;
        string attr;
        string mode;
    } entry_attr;

    struct dest_attributes
    {
        // Attributes of the node
        string nr;
        string group;
        string type;
        string address;
        string displayed;
        string depend;
        // Direct value of node
        string attr;
        // Childs of the node
        string a;
        string t;
    } dest_attr;

    struct source_attributes
    {
        string nr;
        string group;
        string type;
        string address;
        string displayed;
        string a;
        string t;
        string attr;
    } src_attr;

    string mnemonic; //All opcodes have mnemonics
    string prefix; //Prefix of the opcode, is always present
    string sec_opcode; //Secondary opcode
    string proc_start; // opcode's introductory processor
    string proc_end; //opcode's terminating processor
    string instr_ext; // instruction extension, which the opcode belongs to -> #PCDATA

    //main group, sub-group, sub-sub-group: ....Group of what?, seriously :/
    string group1;
    string group2;
    string group3;

    // Like in MOV mnemonics
    string dst; //Destination
    string src; //Source: This may have several values...TODO

    //flags in rFlags register
    string test_f;  //Tested flag
    string modif_f; //Modified flag
    string def_f;   //Defined flag
    string undef_f; //Undefined flag
    string f_vals;  //Flag values in rFlags register;

    //Flags in x87 fpu flags
    string test_f_fpu;
    string modif_f_fpu;
    string def_f_fpu;
    string undef_f_fpu;
    string f_vals_fpu;

    //Notes...
    string note;
} myOpcode;

void print_opcode_struct(struct Opcode_info opcode)
{
	/*
	 * Prints a Opcode_info fields
	 */
    cout << "Mnemonic: " << opcode.mnemonic << endl;

    cout << "Entry values: \n\t Direction: " << opcode.entry_attr.direction;
    cout << "\t Op size: " << opcode.entry_attr.op_size;
    cout << "\t R: " << opcode.entry_attr.r;
    cout << "\t Lock: " << opcode.entry_attr.lock;
    cout << "\t Mode: " << opcode.entry_attr.mode;
    cout << "\t Attribute: " << opcode.entry_attr.attr << endl;

    cout << "Dest values: \n\t NR: " << opcode.dest_attr.nr;
    cout << "\t Group: " << opcode.dest_attr.group;
    cout << "\t Type: " << opcode.dest_attr.type;
    cout << "\t Address: " << opcode.dest_attr.address;
    cout << "\t Displayed: " << opcode.dest_attr.displayed;
    cout << "\t Depend: " << opcode.dest_attr.depend;
    cout << "\t A: " << opcode.dest_attr.a ;
    cout << "\t T:" << opcode.dest_attr.t;
    cout << "\t Attribute: " << opcode.dest_attr.attr << endl;

    cout << "Source values: " << endl;
    cout << "\t Nr: " << opcode.src_attr.nr;
    cout << "\t Group: " << opcode.src_attr.group;
    cout << "\t Type: " << opcode.src_attr.type;
    cout << "\t Address :" << opcode.src_attr.address;
    cout << "\t Displayed: " << opcode.src_attr.displayed;
    cout << "\t A: " << opcode.src_attr.a;
    cout << "\t T:" << opcode.src_attr.t;
    cout << "\t Attribute: " << opcode.src_attr.attr << endl;

    cout << "Prefix: " << opcode.prefix << endl;
    cout << "Secondary opcode: " << opcode.sec_opcode << endl;
    cout << "Proc start: " << opcode.proc_start << endl; //Intro_proc
    cout << "Term processor: " << opcode.proc_end << endl;
    cout << "Instruction extension: " << opcode.instr_ext << endl;

    cout << "Groups: " << endl;
    cout << "\t Main group: " << opcode.group1;
    cout << "\t Sub-group: " << opcode.group2;
    cout << "\t Sub-sub-group: " << opcode.group3 << endl;

    cout << "Destination: " << opcode.dst << endl;
    cout << "Source(s): " << opcode.src << endl;

    cout << "Flags: " << endl;
    cout << "\t Tested flag: " << opcode.test_f;
    cout << "\t Modified flag: " << opcode.modif_f;
    cout << "\t Defined flag: " << opcode.def_f;
    cout << "\t Undefined flag: " << opcode.undef_f;
    cout << "\t rFlag reg value: " << opcode.f_vals << endl;

    cout << "FPU Flags: " << endl;
    cout << "\t Tested FPU flag: " << opcode.test_f_fpu;
    cout << "\t Modified FPU flag: " << opcode.modif_f_fpu;
    cout << "\t Defined FPU flag: " << opcode.def_f_fpu;
    cout << "\t Undefined FPU flag: " << opcode.undef_f_fpu;
    cout << "\t rFlag reg FPU value: " << opcode.f_vals_fpu << endl;

    cout << "Notes: " << opcode.note << endl;

}


void is_binary(string file)
{
	/*
	 * Using the utility file, verifies if the input file
	 * is a binary file
	 * The program will exit returning -1 if the file is not a
	 * binary or elf file or if the file does not exists
	 * Returns void otherwise
	 */
    ifstream my_dataFile;
    string cmd = "file -b -e soft ";
    string output = "";
    char *file_chr = (char*)file.c_str();
    cmd = cmd + file;
    cmd = cmd + " > file_type.txt 2>&1";
    char *command = (char*)cmd.c_str();
    size_t found;

    ifstream check_file;
    check_file.open(file_chr);
    if (check_file.is_open())
    {
        system(command);
        my_dataFile.open("./file_type.txt");

        getline(my_dataFile, output);
        found = output.find("data");

        if (found == 0)
        {
            cout << "Detected binary/object file" << endl;
        }
        else
        {
            cout << "Detected NON binary/object file" << endl;
            exit(-1);
        }
        my_dataFile.close();

    }
    else
    {
        cout << "File: " <<  file <<" provided does not exists" << endl;
        exit(-1);
    }

}


FILE* open_file(char *file_name, const char *mode)
{
    /*
        Received parameters: file_name and mode.
        Example: open_file("my_file.txt", "r");
        Opens a file a returns the pointer to the file.
        Please note this function does not close the file.
        The system will exit from the program if there is a problem
        reading from the file.
    */
    FILE *fp;
    fp = fopen(file_name, mode);
    if (fp == 0)
    {
        cout << "Failed to open file " << file_name << endl;
        exit(-1);
    }
    return fp;

}

unsigned long get_file_size(char *file_name)
{
    /*
    Unsigned long function.
    Receives a file and opens the file
    Returns the size of a file in bytes.
    */
    unsigned long size = 0;
    FILE *fp;
    fp = open_file(file_name, "r");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);
    fclose(fp);
    return size;
}

void file_size_limits(unsigned long kb)
{
    /*
    Void function
    Receives the size of a file in KB, unsigned long number.

    Function may exit with -1 if file size is lower than 1kb
    or greater than 100mb (1024kb*100)
    */
    int hundred_mb_in_kb = 1024 * 100;
    if (kb < 1)
    {
        cout << "Your program is too small to analyze." << endl;
    }
    else if (kb > hundred_mb_in_kb)
    {
        cout << "Your program is too big to analyze." << endl;
    }
    else
    {
        cout << "Your program has a correct size to be analyzed." << endl;
    }
}

void print_binary_file(char *file_name, unsigned long file_size)
{
    /*
    Void function.
    Function requires two arguments: the file name and the file size.
    Prints the content of a binary file, byte per byte.
    Content is shown as a char (Data type).
    */
    FILE *fp;
    char counter;
    int checker;

    fp = open_file(file_name, "rb");

    printf("Opening %s and showing its binary contents.\n\n\n\n", file_name);
    /* read one character at a time from file, stopping at EOF, which
       indicates the end of the file.  Note that the idiom of "assign
       to a variable, check the value" used below works because
       the assignment statement evaluates to the value assigned. */

    // We only print chars with value of less than 32 and less than 126,
    // those chars are printable (ASCII)
    // For more information check: http://en.wikipedia.org/wiki/ASCII
    while  ( ( counter = fgetc(fp) ) != EOF )
    {
        checker = (int)counter;
        if ((checker < 32) || (checker > 126))
        {
            printf( ".");
        }
        else
        {
            printf( "%c", counter);
        }
    }

    printf("End of file\n");
    rewind(fp);
    fclose(fp);
}

void print_binary_file_hex(char *file_name, unsigned long file_size)
{
    /*
    Void function.
    Function requires two arguments: the file name and the file size.
    Prints the content of a binary file in hexadecimal.
    */
    printf("Opening %s and showing its binary contents in Hex.\n\n\n\n", file_name);
    FILE *fp;
    //unsigned int    size_file_content = 0;
    long int        addr = 0, counter = 0, byte_counter = 0;
    long            m = 0, n = 0;
    unsigned char   *buf;
    unsigned char   buffer[16]; //Reduce this to 15?

    fp = open_file(file_name, "rb");

    /*
    While we can keep reading from the file
    We are going to read 16 bytes (Hex) per cycle
    In size of unsigned chars
    byte_counter variable will always have a value of 16
    maybe by except for the last chunk of bytes :P
    */

    cout << "Dec    Hex                          MACHINE CODE                  Strings" <<endl;
    while ((byte_counter = (long)fread(buffer, sizeof(unsigned char), 16, fp)) > 0 )
    {
        buf = buffer;
        /*
          Print the address in decimal and hexadecimal.
          Leaving enough space for 64 bits too
        */
        cout << dec << addr << "\t" << hex << addr << "\t";
        addr = addr + 16;
        /*
          Print 16 data items, in pairs, in hexadecimal.
        */
        counter = 0;
        for (m = 0; m < 16; m++)
        {
            counter = counter + 1;
            if (counter <= byte_counter)
            {
                //cout << setfill('0') << setw(2) << hex << *buf << " "; // why is not working??!
                printf("%02X ", *buf);
                *buf = *buf++;
            }
        }

        /*
          Print the printable characters, or a period if unprintable.
        */
        printf (" " );
        counter = 0;
        for (n=0; n<16; n++ )
        {
            counter = counter + 1;
            if (counter <= byte_counter)
            {
                if ((buffer[n] < 32) || (buffer[n] > 126))
                {
                    cout << ".";
                }
                else
                {
                    cout << buffer[n];
                }
            }
        }
        cout << endl;
    }
    printf("End of file\n");
    rewind(fp);
    fclose(fp);
}

void read_file_type_elf(char *file_name)
{
    /*
    Retrieves the file type as recognized by the elf library.
    */

    printf("READ ELF HEADER function...\n");
    string type_elf;
    char *id, bytes[5];
    int fp, i;
    size_t n;

    Elf *e;
    Elf_Kind ek;
    GElf_Ehdr ehdr;

    fp = open(file_name, O_RDONLY, 0);
    if (fp == 0)
    {
        printf("Failed to open file...\n");
        return;
    }

    e = elf_begin(fp, ELF_C_READ, NULL);
    i = gelf_getclass(e);
    id = elf_getident(e, NULL);

    ek = elf_kind(e);
    switch (ek)
    {
    case ELF_K_AR:
        type_elf = "ar(1) archive";
        break;
    case ELF_K_ELF:
        type_elf = "elf object";
        break;
    default:
        type_elf ="unrecognized";
    }

    cout << "File name: "<< file_name << "\t Elf type: " << type_elf << endl;

    for(i=0; i<=EI_ABIVERSION; i++)
    {
        vis(bytes, id[i], VIS_WHITE, 0);
        printf("['%s' %X]", bytes, id[i]);
    }

    printf("\n");


#define PRINT_FMT   "   %-20s 0x%jx\n"
#define PRINT_FIELD(N)  do{\
            (void)printf(PRINT_FMT, #N, (uintmax_t)ehdr.N);\
    }while(0)

    //print ELF executable header
    PRINT_FIELD(e_type);
    PRINT_FIELD(e_machine);
    PRINT_FIELD(e_version);
    PRINT_FIELD(e_entry);
    PRINT_FIELD(e_phoff);
    PRINT_FIELD(e_shoff);
    PRINT_FIELD(e_flags);
    PRINT_FIELD(e_ehsize);
    PRINT_FIELD(e_phentsize);
    PRINT_FIELD(e_shentsize);


    if(elf_getshdrnum(e,&n)!= 0)
    {
        errx(EX_SOFTWARE, "getshdrnum() failed: %s.", elf_errmsg(-1));
    }

    (void)printf(PRINT_FMT, "(shnum)", (uintmax_t)n);
    if(elf_getshdrstrndx(e,&n)!=0)
    {
        errx(EX_SOFTWARE, "getshdrstrndx() failed: %s.", elf_errmsg(-1));
    }

    (void)printf(PRINT_FMT, "(shstrndx)", (uintmax_t)n);

    if(elf_getphdrnum(e,&n)!=0)
    {
        errx(EX_SOFTWARE,"getphdrnum()failed:%s.", elf_errmsg(-1));
    }

    (void)printf(PRINT_FMT, "(phnum)", (uintmax_t)n);

    elf_end(e);
    close(fp);

}

void read_elf_exe_header(char *file_name)
{

    /*
     * Reads the executable header of an elf file
     * print the information
    */
    printf("READ ELF EXECUTABLE HEADER\n");

    char *id;
    int fp, i;
    size_t n;

    Elf *e;
    Elf_Kind ek;
    GElf_Ehdr ehdr;


    fp = open(file_name, O_RDONLY, 0);
    if (fp == 0)
    {
        printf("Failed to open file...\n");
        return;
    }

    e = elf_begin(fp, ELF_C_READ, NULL);
    i = gelf_getclass(e);
    id = elf_getident(e, NULL);
    ek = elf_kind(e);

#define PRINT_FMT_EHDR  "   %-20s 0x%jx\n"
#define PRINT_FIELD_EHDR(N) (void)printf(PRINT_FMT_EHDR, #N, (uintmax_t)ehdr.N); //while(0)

//print ELF executable header
    PRINT_FIELD_EHDR(e_type);
    PRINT_FIELD_EHDR(e_machine);
    PRINT_FIELD_EHDR(e_version);
    PRINT_FIELD_EHDR(e_entry);
    PRINT_FIELD_EHDR(e_phoff);
    PRINT_FIELD_EHDR(e_shoff);
    PRINT_FIELD_EHDR(e_flags);
    PRINT_FIELD_EHDR(e_ehsize);
    PRINT_FIELD_EHDR(e_phentsize);
    PRINT_FIELD_EHDR(e_shentsize);


    if(elf_getshdrnum(e,&n)!= 0)
    {
        errx(EX_SOFTWARE, "getshdrnum() failed: %s.", elf_errmsg(-1));
    }

    (void)printf(PRINT_FMT_EHDR, "(shnum)", (uintmax_t)n);
    if(elf_getshdrstrndx(e,&n)!=0)
    {
        errx(EX_SOFTWARE, "getshdrstrndx() failed: %s.", elf_errmsg(-1));
    }

    (void)printf(PRINT_FMT_EHDR, "(shstrndx)", (uintmax_t)n);

    if(elf_getphdrnum(e,&n)!=0)
    {
        errx(EX_SOFTWARE,"getphdrnum()failed:%s.", elf_errmsg(-1));
    }

    (void)printf(PRINT_FMT_EHDR, "(phnum)", (uintmax_t)n);

    elf_end(e);
    close(fp);

}

void print_ptype(size_t pt)
{
    string s;
    /*
        Define tutorial: //http://www.zator.com/Cpp/E4_9_10b.htm
        Basically, V is going to be replaced by the string
        sent to C(word) and using ## is going to concatenate both strings,
        before and after the ##
        */
#define C(V) case PT_##V: s = #V; break
    switch (pt)
    {
        C(NULL);
        C(LOAD);
        C(DYNAMIC);
        C(INTERP);
        C(NOTE);
        C(SHLIB);
        C(PHDR);
        C(TLS);
        //C(SUNW_UNWIND); These are suppose to be in elf.h, need to look newest version
        C(SUNWBSS);
        C(SUNWSTACK);
        //C(SUNWDTRACE);
        //C(SUNWCAP);
    default:
        s = "unknown";
        break;
    }
    cout << " \"" << s << " \"";
#undef C
}

void  read_elf_program_header(char *file_name)
{
	/*
	 * Prints the elf header of the program
	 */ 

    int i, fd;
    Elf *e;
    char *id, bytes[5];
    size_t n;
    GElf_Phdr phdr;

    fd = open(file_name, O_RDONLY, 0);
    if (fd == 0)
    {
        printf("Failed to open file...\n");
        return;
    }


    e = elf_begin(fd, ELF_C_READ, NULL);
    i = gelf_getclass(e);
    id = elf_getident(e, NULL);
    //ek = elf_kind(e);

    for(i=0; i<n; i++)
    {
        if(gelf_getphdr(e, i, &phdr) != &phdr)
        {
            //errx(EX_SOFTWARE,"getphdr() failed:%s.", elf_errmsg(-1));
            printf("End of program header.\n");
            break;
        }
        printf("PHDR :\n");
#define PRINT_FMT_PHDR   "%-20s0x%jx\n"
#define PRINT_FIELD_PHDR(N) printf(PRINT_FMT_PHDR, #N, (uintmax_t) phdr.N);

        PRINT_FIELD_PHDR(p_type);
        print_ptype(phdr.p_type);
        PRINT_FIELD_PHDR(p_offset);
        PRINT_FIELD_PHDR(p_vaddr);
        PRINT_FIELD_PHDR(p_paddr);
        PRINT_FIELD_PHDR(p_filesz);
        PRINT_FIELD_PHDR(p_memsz);
        PRINT_FIELD_PHDR(p_flags);
        (void) printf("[");
        if(phdr.p_flags&PF_X)
        {
            (void) printf("execute");
        }
        if(phdr.p_flags&PF_R)
        {
            (void) printf("read");
        }
        if(phdr.p_flags&PF_W)
        {
            (void) printf("write");
        }
        printf("]");
        PRINT_FIELD_PHDR(p_align);
    }
    elf_end(e);
    close(fd);
}

void elf_check_up(char *file_name)
{
    /*
     * Basic sanity tests for libelf
    */

    printf("Basic check to elf structs...\n");

    int i, fd;
    Elf *e;
    char *id, bytes[5];
    size_t n;
    Elf_Kind ek;
    GElf_Ehdr ehdr;
    fd = open(file_name, O_RDONLY, 0);
    if (fd < 0)
    {
        printf("Failed to open file...\n");
        return;
    }

    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        errx(EX_SOFTWARE, "ELF library init failed %s", elf_errmsg(-1));
    }

    e = elf_begin(fd, ELF_C_READ, NULL);
    i = gelf_getclass(e);
    id = elf_getident(e, NULL);

    if (e == NULL)
    {
        errx(EX_SOFTWARE, "elf begin() failed: %s", elf_errmsg(-1));
    }

    if (elf_kind(e) != ELF_K_ELF)
    {
        errx(EX_SOFTWARE, "elf_begin() failed %s", elf_errmsg(-1));
    }

    if (gelf_getehdr(e, &ehdr) == NULL)
    {
        errx(EX_SOFTWARE, "getehdr() failed: %s", elf_errmsg(-1));
    }


    if (i == ELFCLASSNONE)
    {
        errx(EX_SOFTWARE, "getclass() failed: %s", elf_errmsg(-1));
    }


    if(id == NULL)
    {
        errx(EX_SOFTWARE, "getident() failed: %s", elf_errmsg(-1));
    }

    if(elf_getphdrnum(e,&n)!=0)
    {
        errx(EX_DATAERR,"elf_getphdrnum() failed: %s.", elf_errmsg(-1));
    }


    close(fd);
    printf("Basic ELF checkup passed.\n\n");

}


string non_empty_val(string value, string result)
{

    if (value.size())
    {
        result = value;
    }
    return result;

}


struct Opcode_info get_optcode(string check_opcode)
{
    // Receives a string with the opcode
    // Returns a struct with opcode information
    xml_document doc;
    xml_parse_result result;
    xml_document out;
    Opcode_info myOpcode;
    string current_opcode; //Tmp string to hold mnmonic name only
    string tmp; //Tmp string to hold a value of a node/attribute

    ifstream stream("source_code/x86reference.xml");

    xml_node outOpcodes = out.append_child();
    outOpcodes.set_name("opcodes");

    result = doc.load(stream);
    if(!result)
    {
        cerr << "XML parsing error: " << result.description() << endl;
        exit(-1);
    }

    //cout << "Load result: " << result.description() << ", x86reference version: " << doc.child("x86reference").attribute("version").value() << endl;
    xml_node opcodes = doc.child("x86reference").child("one-byte");
    for(xml_node priop = opcodes.first_child(); priop; priop = priop.next_sibling())
    {
        current_opcode = priop.attribute("value").value();
        if ( check_opcode == current_opcode )
        {
            // OK we have found the opcode, now we need to get the data
            for(xml_node entry = priop.first_child(); entry; entry = entry.next_sibling())
            {
                myOpcode.mnemonic = non_empty_val(tmp=entry.child("syntax").child_value("mnem"), myOpcode.mnemonic);

                // Destination
                myOpcode.dest_attr.nr = non_empty_val(tmp=entry.child("syntax").child("dst").attribute("nr").value(), myOpcode.dest_attr.nr);
                myOpcode.dest_attr.group = non_empty_val(tmp=entry.child("syntax").child("dst").attribute("group").value(), myOpcode.dest_attr.group);
                myOpcode.dest_attr.type = non_empty_val(tmp=entry.child("syntax").child("dst").attribute("type").value(), myOpcode.dest_attr.type);
                myOpcode.dest_attr.address = non_empty_val(tmp=entry.child("syntax").child("dst").attribute("address").value(), myOpcode.dest_attr.address);
                myOpcode.dest_attr.displayed = non_empty_val(tmp=entry.child("syntax").child("dst").attribute("displayed").value(), myOpcode.dest_attr.displayed);
                myOpcode.dest_attr.depend = non_empty_val(tmp=entry.child("syntax").child("dst").attribute("depend").value(), myOpcode.dest_attr.depend);
                myOpcode.dest_attr.a = non_empty_val(tmp=entry.child("syntax").child("dst").child_value("a"), myOpcode.dest_attr.a);
                myOpcode.dest_attr.t = non_empty_val(tmp=entry.child("syntax").child("dst").child_value("t"), myOpcode.dest_attr.t);
                myOpcode.dest_attr.attr = non_empty_val(tmp=entry.child("syntax").child_value("dst"), myOpcode.dest_attr.attr);

                // SRC
                myOpcode.src_attr.nr = non_empty_val(tmp=entry.child("syntax").child("src").attribute("nr").value(), myOpcode.src_attr.nr);
                myOpcode.src_attr.group = non_empty_val(tmp=entry.child("syntax").child("src").attribute("group").value(), myOpcode.src_attr.group);
                myOpcode.src_attr.type = non_empty_val(tmp=entry.child("syntax").child("src").attribute("type").value(), myOpcode.src_attr.type);
                myOpcode.src_attr.address = non_empty_val(tmp=entry.child("syntax").child("src").attribute("address").value(), myOpcode.src_attr.address);
                myOpcode.src_attr.displayed = non_empty_val(tmp=entry.child("syntax").child("src").attribute("displayed").value(), myOpcode.src_attr.displayed);
                myOpcode.src_attr.a = non_empty_val(tmp=entry.child("syntax").child("src").child_value("a"), myOpcode.src_attr.a);
                myOpcode.src_attr.t = non_empty_val(tmp=entry.child("syntax").child("src").child_value("t"), myOpcode.src_attr.t);
                myOpcode.src_attr.attr = non_empty_val(tmp=entry.child("syntax").child_value("src"), myOpcode.src_attr.attr);

				//Entry child values
                myOpcode.entry_attr.direction = non_empty_val(tmp=entry.attribute("direction").value(), myOpcode.entry_attr.direction);
                myOpcode.entry_attr.op_size = non_empty_val(tmp=entry.attribute("op_size").value(), myOpcode.entry_attr.op_size);
                myOpcode.entry_attr.r = non_empty_val(tmp=entry.attribute("r").value(), myOpcode.entry_attr.r);
                myOpcode.entry_attr.lock = non_empty_val(tmp=entry.attribute("lock").value(), myOpcode.entry_attr.lock);
                myOpcode.entry_attr.attr = non_empty_val(tmp=entry.attribute("attr").value(), myOpcode.entry_attr.attr);
                myOpcode.entry_attr.mode = non_empty_val(tmp=entry.attribute("mode").value(), myOpcode.entry_attr.mode);

                myOpcode.prefix = non_empty_val(tmp=entry.child_value("pref"), myOpcode.prefix);
                myOpcode.sec_opcode = non_empty_val(tmp=entry.child_value("sec_opcd"), myOpcode.sec_opcode);
                myOpcode.proc_start = non_empty_val(tmp=entry.child_value("proc_start"), myOpcode.proc_start);
                myOpcode.proc_end = non_empty_val(tmp=entry.child_value("proc_end"), myOpcode.proc_end);
                myOpcode.instr_ext = non_empty_val(tmp=entry.child("entry").child_value("instr_ext"), myOpcode.instr_ext);

                //Groups values
                myOpcode.group1 = non_empty_val(tmp=entry.child_value("grp1"), myOpcode.group1);
                myOpcode.group2 = non_empty_val(tmp=entry.child_value("grp2"), myOpcode.group2);
                myOpcode.group3 = non_empty_val(tmp=entry.child_value("grp3"), myOpcode.group3);

				//Flags values
                myOpcode.test_f = non_empty_val(tmp=entry.child_value("test_f"), myOpcode.test_f);
                myOpcode.modif_f = non_empty_val(tmp=entry.child_value("modif_f"), myOpcode.modif_f);
                myOpcode.def_f = non_empty_val(tmp=entry.child_value("def_f"), myOpcode.def_f);
                myOpcode.undef_f = non_empty_val(tmp=entry.child_value("undef_f"), myOpcode.undef_f);
                myOpcode.f_vals = non_empty_val(tmp=entry.child_value("f_vals"), myOpcode.f_vals);

				//FPU Flags values
                myOpcode.test_f_fpu = non_empty_val(tmp=entry.child_value("test_f_fpu"), myOpcode.test_f_fpu);
                myOpcode.modif_f_fpu = non_empty_val(tmp=entry.child_value("modif_f_fpu"), myOpcode.modif_f_fpu);
                myOpcode.def_f_fpu = non_empty_val(tmp=entry.child_value("def_f_fpu"), myOpcode.def_f_fpu);
                myOpcode.undef_f_fpu = non_empty_val(tmp=entry.child_value("undef_f_fpu"), myOpcode.undef_f_fpu);
                myOpcode.f_vals_fpu = non_empty_val(tmp=entry.child_value("f_vals_fpu"), myOpcode.f_vals_fpu);

                myOpcode.dst = non_empty_val(tmp=entry.child("syntax").child("dst").value(), myOpcode.dst);
                myOpcode.src = non_empty_val(tmp=entry.child("syntax").child("src").value(), myOpcode.src);
            }
            print_opcode_struct(myOpcode);
            return myOpcode;
        }

    }
}


int main(int argc, char *argv[])
{
    extern char *optarg;
    extern int optind, optopt, opterr;

    unsigned long file_size_bytes = 0;
    unsigned long file_size_kb = 0;
    char *filename;
    string opcode;

    cout << "*****Ocampo Coronado, Francisco Omar A00354312******" << endl;
    int opt = 0;
    bool show_elf = true;
    while( ((opt = getopt(argc, argv, "nf:o:")) != -1))
    {
        switch( opt )
        {
        case 'n':
            show_elf = false;
            cout << "Not showing elf headers" << endl;
            break;
        case 'f':
            filename = optarg;
            cout << "File to be analyzed: " << filename << endl;
        case 'o':
            opcode = optarg;
            cout << "Opcode to be analyzed: " << opcode << endl;
        case '?':
            cout << "unknown arg " << optopt << endl;
            break;
        }
    }


    is_binary(filename);
    file_size_bytes = get_file_size(argv[1]);
    file_size_kb = file_size_bytes/1024;
    //get_optcode(opcode);
    //exit(0);
    file_size_limits(file_size_kb);

    printf("The file size of the file provided is (in bytes): %li\n", file_size_bytes);
    printf("The file size of the file provided is (in KB): %li\n", file_size_kb);

    print_binary_file_hex(filename, file_size_bytes);
    if (show_elf)
    {
        elf_check_up(filename);
        read_file_type_elf(filename);
        read_elf_exe_header(filename);
        read_elf_program_header(filename);
    }

    exit(0);
}
