#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  char *buf = malloc(10);
  free(buf);
  *(int*)buf = 0x41424344;
  return 0;
}
