#include <stdio.h>

int my_array[] = {1, 2, 3, 4, 5, 6};
int *ptr;

int main(){
    int i;
    ptr = &my_array[0]; // ptr = my_array; is identical, the name of the array is the pointer to the array.

    printf("\n");
    for (i = 0; i < sizeof(my_array)/sizeof(int); i++)
    {
        printf("my_array[%d] = %d      ", i, my_array[i]);
        printf("ptr + %d = %d\n", i, *ptr++);
    }

    return 0;

}
