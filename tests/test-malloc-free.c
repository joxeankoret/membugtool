#include<stdio.h>
#include<stdlib.h>
#include<time.h>

int main(int argc, char **argv)
{
  int i=10000;
  char *buff=NULL;
  srand(time(NULL));

  while (i--)
  {
    buff = malloc((rand() % 64) + 1);
    buff = realloc(buff, (rand() % 64) + 1);
    free(buff);
  }

  return 0;
}
