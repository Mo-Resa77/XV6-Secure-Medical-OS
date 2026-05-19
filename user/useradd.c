#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  // Validate command arguments
  // Correct format:
  // useradd <username> <password> <uid>
  if(argc != 4){
    printf("Usage: useradd <name> <password> <uid>\n");
    exit(1);
  }

  // Buffer to store the hashed password
  char hashed[32];

  // Buffer to build the complete passwd record
  char line[128];

  // Requirement 1.3:
  // Hash the password before storing it
  // to prevent plaintext credential leaks
  hash_password(argv[2], hashed);

  // Requirement 1.1:
  // Construct passwd-style entry:
  // username:hashedpassword:uid\n

  int p = 0;

  // Copy username into line buffer
  for(int i = 0; argv[1][i]; i++)
    line[p++] = argv[1][i];

  // Add separator ':'
  line[p++] = ':';

  // Copy hashed password into line buffer
  for(int i = 0; hashed[i]; i++)
    line[p++] = hashed[i];

  // Add separator ':'
  line[p++] = ':';

  // Copy UID into line buffer
  for(int i = 0; argv[3][i]; i++)
    line[p++] = argv[3][i];

  // Add newline to terminate passwd record
  line[p++] = '\n';

  // Null terminate the string
  line[p] = '\0';

  // Open passwd database
  // O_CREATE creates the file if it does not exist
  // O_RDWR allows reading and writing
  int fd = open("passwd", O_CREATE | O_RDWR);

  if(fd < 0){
    printf("useradd: cannot open passwd\n");
    exit(1);
  }

  // Move file cursor manually to the end of file
  // xv6 lacks append mode support like Linux
  char trash[512];

  while(read(fd, trash, sizeof(trash)) > 0)
    ;

  // Write the full passwd entry in one operation
  // This prevents fragmented or corrupted output
  write(fd, line, strlen(line));

  // Close passwd database safely
  close(fd);

  // Display confirmation message
  printf("Security Update: User '%s' registered with UID %s\n",
         argv[1],
         argv[3]);

  exit(0);
}
