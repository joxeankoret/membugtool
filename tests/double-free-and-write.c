#include <stdlib.h>

int main(void)
{
    char *buf;

    buf = malloc(6666);
    free(buf);
    free(buf);

    buf[0] = 'a';
    buf[1] = 'b';
    buf[2] = 'c';
    buf[3] = 'd';

    buf = 0x41424344;
    buf[0] = 'A';
    free(buf);
    return 0;
}

