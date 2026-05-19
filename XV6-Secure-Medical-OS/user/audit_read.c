#include "kernel/types.h"
#include "user/user.h"

int main(void) {
  // 1. Ask the system: Who am I?
  if (getuid() != 0) {
    printf("EPERM: Access denied (admin only)\n");
    exit(1);
  }

  // 2. If user is admin, call the syscall
  if (audit_read() < 0) {
    printf("Error: Kernel audit buffer is empty or failed.\n");
  } else {
    printf("\n[SUCCESS]: Audit log retrieved successfully.\n");
  }

  exit(0);
}
