#include <stdio.h>

int main(void)
{
  char *buf = malloc(0);
  free(buf);
  return 0;
}
