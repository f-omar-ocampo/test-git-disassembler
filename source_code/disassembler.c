#include <bsd/vis.h>
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


void check_arguments(int argc, char *argv[]);
FILE* open_file(char *file_name, const char *mode);
unsigned long get_file_size(char *file_name);
void file_size_limits(unsigned long kb);
void print_binary_file(char *file_name, unsigned long file_size);
void print_binary_file_hex(char *file_name, unsigned long file_size);
void read_file_type_elf(char *file_name);
void read_elf_exe_header(char *file_name);
void print_ptype(size_t pt);
void read_elf_program_header(char *file_name);
void elf_check_up(char *file_name);
int xml_test();

void check_arguments(int argc, char *argv[])
{
    /*
    Function to handle arguments received by the program.
    Planning to use getops for this.

    For now, it receives one parameter, the name of the file to be analyzed
    */
    if(argc==2)
    {
        cout << "The argument supplied is " << argv[1] << endl;
    }
    else if (argc > 2)
    {
        cout << "Too many arguments received." << endl;
        cout << "Please provide only the name of a file." << endl;
    }

    cout << "The name of the file is " << argv[1] << endl;
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

    
    #define	PRINT_FMT	"   %-20s 0x%jx\n"
    #define	PRINT_FIELD(N)	do{\
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
    Retrieves the file type as recognized by the elf library.
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

#define	PRINT_FMT_EHDR	"   %-20s 0x%jx\n"
#define	PRINT_FIELD_EHDR(N)	(void)printf(PRINT_FMT_EHDR, #N, (uintmax_t)ehdr.N); //while(0)

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
    Void Function.
    Receives
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

int xml_test()
{
	xml_document doc;
    xml_parse_result result;
    xml_document out;

    ifstream stream("x86reference.xml");

    xml_node outOpcodes = out.append_child();
    outOpcodes.set_name("opcodes");

    result = doc.load(stream);
	if(!result)
    {
        cerr << "XML parsing error: " << result.description() << endl;
        return 1;
    }

	cout << "Load result: " << result.description() << ", x86reference version: " << doc.child("x86reference").attribute("version").value() << endl;  
    
  
   /* Loop over all 1 byte opcodes */
    xml_node opcodes = doc.child("x86reference").child("one-byte");
    for(xml_node priop = opcodes.first_child(); priop; priop = priop.next_sibling())
     {
		 cout << "Analyzing opcode: " << priop.attribute("value").value() << endl;
            /* Loop over all entries for each opcode */
            for(xml_node entry = priop.first_child(); entry; entry = entry.next_sibling())
            {
                /* Ignore invalid entries */
                if(string("invd") == entry.attribute("attr").value() ||
                   string("undef") == entry.attribute("attr").value() ||
                   string("null") == entry.attribute("attr").value() ||
                   string("prefix") == entry.child("grp1").first_child().value())
                continue;

				// <entry direction="0" op_size="0" r="yes" lock="yes">
				// Debugging information: Not all the opcodes have this attributes
				// which are in tag <entry>
				cout << "\tDirection: " << entry.attribute("direction").value();
				cout << " Op size: " << entry.attribute("op_size").value();
				cout << " R: " << entry.attribute("r").value();
				cout << " Lock: " << entry.attribute("lock").value() << endl;
				
				// Create a new xml_node based on the next onebyte opcode
				// And create a primary value named primary, which will save the
				// optcode value.
				// Since some op codes have secondary "opcodes" we are going
				// to create a node to save that informaiton, simarly with 
				// the extension.
                xml_node outOp = outOpcodes.append_child();
                outOp.set_name("op");
                outOp.append_attribute("primary") = priop.attribute("value").value();

                if(entry.child("sec_opcd").first_child())
                    outOp.append_attribute("secondary") = entry.child("sec_opcd").first_child().value();

                if(entry.child("opcd_ext").first_child())
                    outOp.append_attribute("extension") = entry.child("opcd_ext").first_child().value();

                string src_type_str;
                string src_size_str;
                string dst_type_str;
                string dst_size_str;

                if(entry.child("syntax").child("src").child("a"))
                {
                    src_type_str = entry.child("syntax").child("src").child("a").first_child().value();
                    src_size_str = entry.child("syntax").child("src").child("t").first_child().value();
                }

                if(entry.child("syntax").child("dst").child("a"))
                {
                    dst_type_str = entry.child("syntax").child("dst").child("a").first_child().value();
                    dst_size_str = entry.child("syntax").child("dst").child("t").first_child().value();
                }

				//cout << src_type_str << src_size_str << dst_type_str << dst_size_str << endl;
                //outOp.append_attribute("modrm") = GetModrmState(src_type_str, dst_type_str);
               // pair<int, int> immediate = GetImmediateState(src_type_str, src_size_str, dst_type_str, dst_size_str);
                //if(immediate.first != 0)
               // {
               //     outOp.append_attribute("imm") = immediate.first;
                //    outOp.append_attribute("imm_size") = immediate.second;
               // }
            }
    }

}


int main(int argc, char *argv[])
{
	unsigned long file_size_bytes = 0;
    unsigned long file_size_kb = 0;

    cout << "*****Ocampo Coronado, Francisco Omar A00354312******" << endl;
	//xml_test();
	//exit(0);
    // argv[1] = "./disassembler"; //hard coded for now.
    //check_arguments(argc, argv);
    //file_size_bytes = get_file_size(argv[1]);
    //file_size_kb = file_size_bytes/1024;

    //file_size_limits(file_size_kb);

    //printf("The file size of the file provided is (in bytes): %li\n", file_size_bytes);
    //printf("The file size of the file provided is (in KB): %li\n", file_size_kb);

    //print_binary_file(argv[1], file_size_bytes);
    //print_binary_file_hex(argv[1], file_size_bytes);
    elf_check_up(argv[1]);
    read_file_type_elf(argv[1]);
    read_elf_exe_header(argv[1]);
    read_elf_program_header(argv[1]);
    exit(0);
}
