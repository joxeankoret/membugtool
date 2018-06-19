#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  printf("*** PROGRAM: malloc(8)\n");
  char *buf = malloc(8);
  printf("*** PROGRAM: free(buf)\n");
  free(buf);
  printf("*** PROGRAM: realloc(buf, 16)\n");
  buf = realloc(buf, 16);
  return 0;
}
