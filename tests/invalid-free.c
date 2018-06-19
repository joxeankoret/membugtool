#include <stdio.h>

int main(void)
{
    char *buf = 0x41424344;
    free(buf);
    printf("How is that possible?\n");
    return 0;
}

