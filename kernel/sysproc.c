#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if(addr + n < addr)
      return -1;
    if(addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}


// Return the current process's user ID
uint64
sys_getuid(void)
{
  return myproc()->uid;        // Returns the UID stored in the current process structure
}

// Set the current process's user ID (to be restricted later)
uint64
sys_setuid(void)
{
  int uid;
  argint(0, &uid);             // Retrieve the integer argument passed from user space
  myproc()->uid = uid;         // Update the process UID to the new value
  return 0;
}




// Declare external variables defined in trap.c
extern struct audit_record audit_log[];
extern int audit_head;

uint64
sys_audit_read(void)
{
  struct proc *p = myproc();

  // Only admin (UID 0) can read the audit log
  if(p->uid != 0){
    return -1;
  }

  printf("\n--- SYSTEM AUDIT LOG (K-Buffer) ---\n");
  printf("TIME | PID | UID | SYSCALL\n");

  for(int i = 0; i < 32; i++){
    int idx = (audit_head + i) % 32;
    struct audit_record *ar = &audit_log[idx];

    // Print only non-empty records
    if(ar->pid > 0){
      // Simple printf format (without complex alignment for now)
      printf("%d | %d | %d | %s\n",
             ar->ticks, ar->pid, ar->uid, ar->syscall_name);
    }
  }

  return 0;
}
