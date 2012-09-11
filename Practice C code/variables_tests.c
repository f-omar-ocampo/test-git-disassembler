#include <stdio.h>

/* Global variables
 * declarations */
char global_file_location[10];
int  global_number_files = 5;

void main(){
    char char_var = 'c';
    int int_var = 2147483647;
    long long_var = 2147483647;
    long long long_long_var = 9223372036854775807;
    unsigned nosing_int_var = 4294967295;
    float float_var = 3.141516;
    double double_var = 3.1415161718;
    int casted_float = (int) float_var;
    
    // Modification of global variable
    global_file_location[0] = '/';
    
    
    printf("Original float %f -> Now casted to int %d \n", float_var, casted_float);
    printf("Global variable %c \n", global_file_location[0]);
    
    //Testing the ++
    printf("Original variable %d \n", global_number_files);
    printf("Now lets do ++var %d \n", ++global_number_files);
    printf("Now lets do var++ %d \n", global_number_files++);
    printf("Wow! Even if we did a var++ we printed the same value!\n");
    printf("Finally lets print the var %d\n", global_number_files);
    
    printf("The variable was modified even if we did not assigned a new value!\n");
    
    
    
}