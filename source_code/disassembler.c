#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <err.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <bsd/vis.h>
//#include <getopt.h>

#define ERR -1
#define TRUE 0
#define FALSE -1

//Elf32_Ehdr *elf_header;		    /* ELF header */
//Elf *elf;                       /* Our Elf pointer for libelf */
//Elf_Scn *scn;                   /* Section Descriptor */
//Elf_Data *edata;                /* Data Descriptor */
//GElf_Sym sym;			        /* Symbol */
//GElf_Shdr shdr;                 /* Section Header */


void elf_check_up(char *file_name);
unsigned long get_file_size(char *file_name);
void file_size_limits(unsigned long kb);
void check_arguments(int argc, char *argv[]);
void print_binary_file(char *file_name, unsigned long file_size);
void read_binary_file(char *file_name, unsigned long file_size);
void read_elf_header(char *file_name);
void elf_check_up(char *file_name);

unsigned long get_file_size(char *file_name)
{
    /*
    Unsigned long function.
    Receives a file and opens the file
    Returns the size of a file in bytes.
    */
    long size = 0;
    FILE *fp;
    fp = fopen(file_name, "r");
    if ( fp == 0)
    {
        printf("Unable to open file %s \n", file_name);
        exit(1);
    }
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
        printf("Your program is too small to analyze.\n");
    }
    else if (kb > hundred_mb_in_kb)
    {
        printf("Your program is too big to analyze.\n");
    }
    else
    {
        printf("Your program has a correct size to be analyzed.\n");
    }
}

void check_arguments(int argc, char *argv[])
{
    /*
    Function to handle arguments received by the program.
    Planning to use getops for this.

    For now, it receives one parameter, the name of the file to be analyzed
    */
    if(argc==2)
    {
        printf("The argument supplied is %s \n", argv[1]);
    }
    else if (argc > 2)
    {
        printf("Too many arguments received. \n");
        printf("Please provide only the name of a file. \n");
    }

    printf("The name of the file is %s \n", argv[0]);
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
    int  counter = 0;

    fp = fopen(file_name, "rb");
    if ( fp == 0)
    {
        printf("Unable to open file %s \n", file_name);
        exit(1);
    }

    printf("Opening %s and showing its binary contents.\n\n\n\n", file_name);
    /* read one character at a time from file, stopping at EOF, which
       indicates the end of the file.  Note that the idiom of "assign
       to a variable, check the value" used below works because
       the assignment statement evaluates to the value assigned. */
    while  ( ( counter = fgetc(fp) ) != EOF )
    {
        printf( "%c", (char)counter );
    }

    printf("End of file\n");
    rewind(fp);
    fclose(fp);
}

void read_binary_file(char *file_name, unsigned long file_size)
{
    /*
    Void function.
    Function requires two arguments: the file name and the file size.
    Prints the content of a binary file in hexadecimal.
    */
    printf("Opening %s and showing its binary contents in Hex.\n\n\n\n", file_name);
    FILE *fp;
    unsigned int    size_file_content = 0;
    long int        addr, counter, counter2;
    long            m, n;
    unsigned char   *b;
    unsigned char   buffer[20];


    fp = fopen(file_name, "rb");
    printf("%p", fp);
    if (fp == 0)
    {
        printf("Unable to open file %s \n", file_name);
        exit(1);
    }

    // While we can keep reading from the file
    // We are going to read 16 bytes (Hex) per cycle
    // In size of unsigned chars
    while ((counter = (long)fread(buffer, sizeof(unsigned char), 16, fp)) > 0 )
    {
        b = buffer;
        /*
          Print the address in decimal and hexadecimal.
        */
        printf ("%5d %08lx  ", (int)addr, addr);
        addr = addr + 16;
        /*
          Print 16 data items, in pairs, in hexadecimal.
        */
        counter2 = 0;
        for (m = 0; m<16; m++)
        {
            counter2 = counter2 + 1;
            if (counter2 <= counter)
            {
                printf("%02x", *b++);
            }
            else
            {
                printf (" ");
            }
            printf (" ");
        }
        /*
          Print the printable characters, or a period if unprintable.
        */
        printf (" " );
        counter2 = 0;
        for (n=0; n<16; n++ )
        {
            counter2 = counter2 + 1;
            if (counter2 <= counter)
            {
                if ((buffer[n] < 32) || (buffer[n] > 126))
                {
                    printf ("%c", '.');
                }
                else
                {
                    printf ("%c", buffer[n]);
                }
            }
        }
        printf( "\n" );
    }
    printf("End of file\n");
    rewind(fp);
    fclose(fp);
}

void read_elf_header(char *file_name)
{
    printf("READ ELF HEADER function...\n");


    char *k;
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

    printf("%s: %d bit ELF object\n", file_name, i == ELFCLASS32 ? 32 : 64);
    printf("%3s e_ident[0..%1d] %7s", " ", EI_ABIVERSION, " ");


    ek = elf_kind(e);
    switch (ek)
    {
    case ELF_K_AR:
        k = "ar(1) archive";
        break;
    case ELF_K_ELF:
        k = "elf object";
        break;
    default:
        k ="unrecognized";
    }
    printf("%s: %s\n", file_name, k);

    for(i=0; i<=EI_ABIVERSION; i++)
    {
        (void) vis(bytes, id[i], VIS_WHITE, 0);
        (void) printf("['%s' %X]", bytes, id[i]);
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

    close(fd);
    printf("Basic ELF checkup passed.\n\n");

}


int main (int argc, char *argv[])
{
    unsigned long file_size_bytes = 0;
    unsigned long file_size_kb = 0;

    printf("*****This is the unfamous disassembler proyect******\n");
    printf("*****Ocampo Coronado, Francisco Omar A00354312******\n");

   // argv[1] = "./disassembler"; //hard coded for now.
    //arguments(argc, argv);
   // file_size_bytes = get_file_size(argv[1]);
   // file_size_kb = file_size_bytes/1024;

    //file_size_limits(file_size_kb);

  //  printf("The file size of the file provided is (in bytes): %li\n", file_size_bytes);
   // printf("The file size of the file provided is (in KB): %li\n", file_size_kb);

    //file_size_limits(file_size_kb);
    //print_binary_file(argv[1], file_size_bytes);
    //read_binary_file(argv[1], file_size_bytes);
    elf_check_up(argv[1]);
    read_elf_header(argv[1]);
    exit(0);
}
