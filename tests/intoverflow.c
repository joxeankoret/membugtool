#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int foo(char *arg, int size)
{
    char *buf;

    if ( strlen(arg) > size )
    {
        printf("Too big!\n");
        return 1;
    }

    buf = malloc(size);
    strcpy(buf, arg);
    printf("Buffer is %s\n", buf);
    free(buf);

    return 0;
}

int main(int argc, char **argv)
{
    if ( argc != 3 )
    {
        printf("Invalid number of arguments!\n");
        return 2;
    }

    return foo(argv[1], atoi(argv[2]));
}

