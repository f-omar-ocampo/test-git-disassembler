#include <stdio.h>

/* Pointer testing
 * Tengo miedo! xD
 */

int main(){
    int j, k;
    int *ptr;
    j = 1;
    k = 2;
    ptr = &k;
    printf("\n");
    printf("j has the value %d and is stored at %p \n", j, (void *)&j);
    printf("k has the value %d and is stored at %p \n", j, (void *)&k);
    printf("ptr has the value %p and is storead at %p \n", ptr, (void *)&ptr);
    printf("The value of the integer pointer to by ptr is %d \n", *ptr);
    return 0;
}
