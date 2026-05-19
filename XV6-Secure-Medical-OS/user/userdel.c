#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

// Buffer used to store one line from the passwd file
char line[128];

// Check whether a passwd entry starts with the target username
// Example:
// line  = "patient:hashedpw:1"
// name  = "patient"
// Returns 1 if matched, otherwise 0
int
starts_with(char *line, char *name)
{
  int i = 0;

  // Compare username character-by-character
  while(name[i] && line[i]){
    if(name[i] != line[i])
      return 0;
    i++;
  }

  // Ensure the username is followed by ':'
  // to avoid partial matches
  if(line[i] == ':')
    return 1;

  return 0;
}

int
main(int argc, char *argv[])
{
  // Validate command usage
  // Correct format:
  // userdel <username>
  if(argc != 2){
    printf("Usage: userdel <username>\n");
    exit(1);
  }

  // Open existing passwd database
  int fd = open("passwd", O_RDONLY);

  // Exit if passwd file does not exist
  if(fd < 0){
    printf("userdel: passwd not found\n");
    exit(1);
  }

  // Create temporary passwd file
  // This file will store all users except the deleted one
  int fd2 = open("passwd.tmp", O_CREATE | O_WRONLY);

  if(fd2 < 0){
    printf("userdel: cannot create temp file\n");
    close(fd);
    exit(1);
  }

  char c;
  int idx = 0;

  // Read passwd file character-by-character
  while(read(fd, &c, 1) == 1){

    // Store current character into line buffer
    line[idx++] = c;

    // End of line detected
    if(c == '\n'){

      // Null-terminate current line
      line[idx] = '\0';

      // Copy line only if it does NOT belong
      // to the user being deleted
      if(!starts_with(line, argv[1])){
        write(fd2, line, idx);
      }

      // Reset buffer index for next line
      idx = 0;
    }
  }

  // Close both files after processing
  close(fd);
  close(fd2);

  // Remove old passwd database
  unlink("passwd");

  // Re-open temporary file for reading
  int oldfd = open("passwd.tmp", O_RDONLY);

  // Create new passwd database
  int newfd = open("passwd", O_CREATE | O_WRONLY);

  char buf[128];
  int n;

  // Copy contents from temporary file
  // back into the new passwd database
  while((n = read(oldfd, buf, sizeof(buf))) > 0){
    write(newfd, buf, n);
  }

  // Close both file descriptors
  close(oldfd);
  close(newfd);

  // Delete temporary file after migration completes
  unlink("passwd.tmp");

  // Display success message
  printf("User '%s' deleted successfully\n", argv[1]);

  exit(0);
}
