#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc < 3){
    fprintf(2, "Usage: chown uid file\n");
    exit(1);
  }
  int uid = atoi(argv[1]);
  if(chown(argv[2], uid) < 0)
    fprintf(2, "chown failed\n");
  exit(0);
}
