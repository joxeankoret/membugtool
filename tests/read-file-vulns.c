#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//----------------------------------------------------------------------
int do_things(char *buf, char size, FILE *fp)
{
  int ret;
  int bytes;
  char c;
  char data[3];

  void *ptr = buf;
  while ( 1 )
  {
    bytes = fread(&c, 1, 1, fp);
    if ( bytes == 0 )
      return -1;
    
    switch ( c )
    {
      case 'A':
        bytes = fread(&data, 1, 4, fp);
        if ( bytes == 0 )
          return -1;

        strcat(buf, data);
        strcat(buf, "\0");
        break;
      case 'M':
        bytes = fread(&c, 1, 1, fp);
        if ( bytes == 0 )
          return -1;
        
        buf = malloc(c);
        break;
      case 'F':
        free(ptr);
        break;
      case 'P':
        printf("%s\n", buf);
        break;
      default:
        ret = strlen(buf);
    }
  }

  return ret;
}

//----------------------------------------------------------------------
int logic(char *filename)
{
  FILE *fp;
  int ret = 0;

  fp = fopen(filename, "rb");
  if ( fp != NULL )
  {
    char magic[4];
    int bytes = fread(magic, 1, sizeof(magic), fp);
    if ( bytes == 4 )
    {
      if ( strcmp(magic, "TEST") != 0 )
      {
        char *buf;
        char size;
        bytes = fread(&size, 1, sizeof(size), fp);
        if ( bytes == sizeof(size) )
        {
          buf = malloc(size);
          if ( buf ) 
          {
            ret = do_things(buf, size, fp);
            free(buf);
          }
          else
          {
            perror("malloc");
            ret = -2;
          }
        }
        else
        {
          perror("fread");
          ret = -2;
        }
      }
      else
      {
        printf("Invalid magic header!\n");
        ret = 2;
      }
    }
    else
    {
      printf("Invalid file size!\n");
      ret = 1;
    }
    fclose(fp);
  }
  else
  {
    perror("fopen");
    ret = -1;
  }

  return ret;
}

//----------------------------------------------------------------------
void usage(char *prog)
{
  printf("Usage: %s <filename>\n", prog);
}

//----------------------------------------------------------------------
int main(int argc, char **argv)
{
  if ( argc != 2 )
  {
    usage(argv[0]);
    exit(1);
  }
  
  return logic(argv[1]);
}
