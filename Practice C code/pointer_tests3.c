#include <stdio.h>
#include <elf.h>

char strA[80] = "A string to be used for demonstration purposes";
char strB[80];

int main(void){
    char *ptrA; //pointer to char
    char *ptrB; //pointer to char
    puts(strA);  //prints strA
    ptrA = strA;  //make ptrA point to strA
    puts(ptrA); //print what prtrA is pointing to
    ptrB = strB; // point ptrB at strB
    putchar('\n');
    while(*ptrA != '\0'){
        *ptrB++ = *ptrA++;
    }
    *ptrB = '\0';
    puts(strB);
    return 0;
}
