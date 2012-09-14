/*
*Print the ELF Program Header Table in an ELF object.
*/
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <bsd/vis.h>

void print_ptype(size_t pt)
{
    char *s;
// Define tutorial: //http://www.zator.com/Cpp/E4_9_10b.htm
//basically, V is going to be replaced by the string
//sent to C(word) and using ## is going to concatenate both strings,
//before and after the ##
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
       // C(SUNW_UNWIND); These are suppose to be in elf.h, need to look newest version
        C(SUNWBSS);
        C(SUNWSTACK);
        //C(SUNWDTRACE);
       // C(SUNWCAP);
    default:
        s="unknown";
        break;
    }
    (void)printf(" \"%s\"",s);
#undef C
}
int main(int argc, char **argv)
{
    int i, fd;
    Elf *e;
    char *id, bytes[5];
    size_t n;
    GElf_Phdr phdr;

    if(argc!=2)
    {
        errx(EX_USAGE, "usage: %s file-name",argv[0]);
    }

    if(elf_version(EV_CURRENT)==EV_NONE)
    {
        errx(EX_SOFTWARE, "ELF library initialization failed: %s", elf_errmsg(-1));
    }

    if((fd=open(argv[1],O_RDONLY,0))<0)
    {
        err(EX_NOINPUT, "Open \"%s\" failed",argv[1]);
    }

    if((e=elf_begin(fd,ELF_C_READ,NULL))==NULL)
    {
        errx(EX_SOFTWARE, "elf_begin() failed: %s.", elf_errmsg(-1));
    }

    if(elf_kind(e)!=ELF_K_ELF)
    {
        errx(EX_DATAERR, "\"%s\"is not an ELFobject.", argv[1]);
    }

    if(elf_getphdrnum(e,&n)!=0)
    {
        errx(EX_DATAERR,"elf_getphdrnum() failed: %s.", elf_errmsg(-1));
    }

    for(i=0; i<n; i++)
    {
        if(gelf_getphdr(e, i, &phdr) != &phdr)
        {
            errx(EX_SOFTWARE,"getphdr() failed:%s.", elf_errmsg(-1));
        }
        (void)printf("PHDR %d :\n");
#define PRINT_FMT   "%-20s0x%jx"
#define PRINT_FIELD(N)  do{\
                                (void)printf(PRINT_FMT, #N, (uintmax_t) phdr.N);\
                            }while (0)
#define NL()    do{\
                        (void)printf("\n");\
                      } while(0)
        PRINT_FIELD(p_type);
        print_ptype(phdr.p_type);
        NL();
        PRINT_FIELD(p_offset);
        NL();
        PRINT_FIELD(p_vaddr);
        NL();
        PRINT_FIELD(p_paddr);
        NL();
        PRINT_FIELD(p_filesz);
        NL();
        PRINT_FIELD(p_memsz);
        NL();
        PRINT_FIELD(p_flags);
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
        NL();
        PRINT_FIELD(p_align);
        NL();
    }
    (void)elf_end(e);
    (void)close(fd);
    exit(EX_OK);
}
