#include "kernel/types.h"
#include "user/user.h"

int main(void) {
  int uid = getuid(); 

  if(uid == 0)
    printf("Current Role: ADMIN (Full System Access)\n");
  else if(uid == 1)
    printf("Current Role: PATIENT (Own records - Read Only)\n"); 
  else if(uid == 2)
    printf("Current Role: DOCTOR (Medical Records Access)\n");
  else
    printf("Current Role: GUEST (UID: %d)\n", uid);

  exit(0);
}
