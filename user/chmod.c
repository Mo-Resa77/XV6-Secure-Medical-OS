#include "kernel/types.h"
#include "user/user.h"

// Helper function to convert octal string (e.g. "755" or "644") to integer
int
octal_to_int(char *s)
{
  int res = 0;
  while(*s >= '0' && *s <= '7'){
    res = (res << 3) | (*s - '0');
    s++;
  }
  return res;
}

int
main(int argc, char *argv[])
{
  if(argc < 3){
    fprintf(2, "Usage: chmod mode file\n");
    exit(1);
  }

  // Convert octal string to integer (better than atoi for permissions)
  int mode = octal_to_int(argv[1]);

  if(chmod(argv[2], mode) < 0)
    fprintf(2, "chmod failed\n");

  exit(0);
}
