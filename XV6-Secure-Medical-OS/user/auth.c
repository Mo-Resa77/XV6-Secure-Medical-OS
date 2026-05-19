#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

// ------------------------------------------------------------
// Authentication utility
// Requirement 1.3
//
// Verifies user credentials using hashed passwords
//
// Usage:
// auth <username> <password>
// ------------------------------------------------------------

// Buffer for reading passwd lines
char line[128];

int
main(int argc, char *argv[])
{
  // Validate arguments
  if(argc != 3){
    printf("Usage: auth <username> <password>\n");
    exit(1);
  }

  // Open passwd database
  int fd = open("passwd", O_RDONLY);

  if(fd < 0){
    printf("auth: passwd database not found\n");
    exit(1);
  }

  // Hash entered password
  char hashed_input[32];

  hash_password(argv[2], hashed_input);

  char c;
  int idx = 0;

  // Read passwd file line by line
  while(read(fd, &c, 1) == 1){

    line[idx++] = c;

    // End of user record
    if(c == '\n'){

      line[idx] = '\0';

      // Parse:
      // username:hashedpassword:uid

      char username[32];
      char stored_hash[32];

      int i = 0;
      int j = 0;

      // Extract username
      while(line[i] != ':' && line[i] != '\0'){
        username[j++] = line[i++];
      }

      username[j] = '\0';

      // Skip :
      i++;

      j = 0;

      // Extract stored hash
      while(line[i] != ':' && line[i] != '\0'){
        stored_hash[j++] = line[i++];
      }

      stored_hash[j] = '\0';

      // Compare usernames
      if(strcmp(username, argv[1]) == 0){

        // Compare hashed passwords
        if(strcmp(stored_hash, hashed_input) == 0){

          printf("Authentication successful\n");

        } else {

          printf("Authentication failed\n");
        }

        close(fd);
        exit(0);
      }

      idx = 0;
    }
  }

  printf("User not found\n");

  close(fd);

  exit(0);
}
