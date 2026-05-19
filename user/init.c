#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

char *sh_args[] = { "sh", 0 };

/* -----------------------------
   ROLE MAPPING (DISPLAY ONLY)
   ----------------------------- */
char* get_role(int uid) {
  if(uid == 0)
    return "ADMIN (Full System Access)";
  else if(uid == 1)
    return "PATIENT (Own Records - Read Only)";
  else if(uid == 2)
    return "DOCTOR (Dosage Logs + Patient Records)";
  else
    return "UNKNOWN ROLE";
}

/* -----------------------------
   SAFE LINE READER (passwd file)
   ----------------------------- */
int readline(int fd, char *buf, int max) {
  int i = 0;
  char c;

  while (i < max - 1) {
    if (read(fd, &c, 1) < 1) break;
    buf[i++] = c;
    if (c == '\n') break;
  }

  if (i == 0) return -1;

  buf[i] = '\0';
  return i;
}

/* -----------------------------
   SPLIT "user:hash:uid"
   ----------------------------- */
void get_field(char *line, char *out, int field_no) {
  int cur = 0, j = 0;

  for (int i = 0; line[i] != '\0' && line[i] != '\n'; i++) {
    if (line[i] == ':') {
      cur++;
      continue;
    }
    if (cur == field_no) {
      out[j++] = line[i];
    }
  }

  out[j] = '\0';
}

int main(void) {
  int pid, wpid;

  /* -----------------------------
     SETUP CONSOLE
     ----------------------------- */
  if (open("console", O_RDWR) < 0) {
    mknod("console", 1, 1);
    open("console", O_RDWR);
  }

  dup(0);
  dup(0);

  for (;;) {

    /* -----------------------------
       EMERGENCY ADMIN CREATION
       ----------------------------- */
    int fd_check = open("passwd", O_RDONLY);

    if (fd_check < 0) {
      char *args[] = { "useradd", "admin", "admin123", "0", 0 };

      if (fork() == 0) {
        exec("useradd", args);
        exit(1);
      }
      wait(0);
    } else {
      close(fd_check);
    }

    /* -----------------------------
       LOGIN PROMPT
       ----------------------------- */
    printf("\n--- SECURE MEDICAL OS LOGIN ---\n");

    char user[32], pass[32], line[128];

    printf("Username: ");
    gets(user, sizeof(user));
    if (strlen(user) > 0)
      user[strlen(user) - 1] = '\0';

    printf("Password: ");
    gets(pass, sizeof(pass));
    if (strlen(pass) > 0)
      pass[strlen(pass) - 1] = '\0';

    /* Hash password */
    char hashed_input[32];
    hash_password(pass, hashed_input);

    int fd = open("passwd", O_RDONLY);
    int auth = 0;
    int uid = -1;

    /* -----------------------------
       AUTHENTICATION
       ----------------------------- */
    if (fd >= 0) {
      while (readline(fd, line, sizeof(line)) > 0) {

        char db_user[32], db_hash[32], db_uid[10];

        get_field(line, db_user, 0);
        get_field(line, db_hash, 1);
        get_field(line, db_uid, 2);

        if (strcmp(user, db_user) == 0 &&
            strcmp(hashed_input, db_hash) == 0) {

          auth = 1;
          uid = atoi(db_uid);
          break;
        }
      }
      close(fd);
    }

    /* -----------------------------
       LOGIN SUCCESS
       ----------------------------- */
    if (auth) {

      printf("Access Granted. Role: %s (UID = %d)\n",
             get_role(uid), uid);

      pid = fork();

      if (pid == 0) {

        /* IMPORTANT: set identity before shell */
        setuid(uid);

        exec("sh", sh_args);

        printf("exec sh failed\n");
        exit(1);
      }

      while ((wpid = wait((int *)0)) >= 0 && wpid != pid);

    } else {
      printf("Login Failed!\n");
    }
  }
}
