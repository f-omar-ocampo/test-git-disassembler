#include <stdio.h>

//This is a comment

/*
This is a comment too
*/

// This is a prototype function
// Are really useful to help the compiler to find the functions
// before the function is defined
// Let's think this a a telephone directory
int sum(int a, int b);


// This is a function
//type   function_name (type argument_name, type arg_name...)
//The type must be the same as the returned value
int sum(int a, int b){
    int suma = 0;
    suma = a + b;
    return suma;
}

main (){
    int suma = 0;
    suma = sum(5, 14);
    printf("%d\n", suma);
    exit(0);
    
}