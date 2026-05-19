#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

void
trapinit(void)
{
  initlock(&tickslock, "time");
}







// Phase 3.2: Audit Ring Buffer Storage
struct audit_record audit_log[AUDIT_BUF_SIZE];
int audit_head = 0;







// Layer 1: Names Mapping
static char *audit_names[] = {
  [1]  "fork",   [2]  "exit",   [3]  "wait",   [4]  "pipe",
  [5]  "read",   [6]  "kill",   [7]  "exec",   [8]  "fstat",
  [9]  "chdir",  [10] "dup",    [11] "getpid", [12] "sbrk",
  [13] "sleep",  [14] "uptime", [15] "open",   [16] "write",
  [17] "mknod",  [18] "unlink", [19] "link",   [20] "mkdir",
  [21] "close",  [22] "whoami", [23] "auth",   [24] "chmod",
  [25] "chown"
};

// Layer 2: Audit Policy (1 = Log it, 0 = Silent)
static char audit_policy[] = {
  [1]  1, [2]  1, [3]  1, [7]  1, [15] 1, [24] 1, [25] 1, // Security & Process events
  [5]  0, [16] 0, [21] 0, [10] 0,                         // Noisy I/O (Silent)
  [22] 1, [23] 1                                          // Identity events
};









































// handle an interrupt, exception, or system call from user space.

// called from, and returns to, trampoline.S

// return value is user satp for trampoline.S to switch to.

//

uint64

usertrap(void)

{

  int which_dev = 0;



  if((r_sstatus() & SSTATUS_SPP) != 0)

    panic("usertrap: not from user mode");



  // send interrupts and exceptions to kerneltrap(),

  // since we're now in the kernel.

  w_stvec((uint64)kernelvec);  //DOC: kernelvec



  struct proc *p = myproc();



  // save user program counter.

  p->trapframe->epc = r_sepc();



  if(r_scause() == 8){

    // system call



    if(killed(p))

     kexit(-1);





// Save the original PC before modification
    uint64 current_pc = p->trapframe->epc;





    // sepc points to the ecall instruction,

    // but we want to return to the next instruction.

    p->trapframe->epc += 4;


// --- Phase 3.1: Trap Pretty Printing (Refined & Clean) ---
    // --- The 2-Layer Audit Logic ---
    int num = p->trapframe->a7;

    // 1. Validity Check: Only audit syscalls that have a name mapping
    // --- Phase 3.1: Professional Smart Audit ---
    if(num > 0 && num < 26 && audit_names[num]) {
        char *name = audit_names[num];
        int should_log = audit_policy[num];

    if(num == 5 || num == 16) {
            uint64 n_bytes = p->trapframe->a2;
            // لو الحجم أكبر من 1 بايت (يعني ملف مش حرف من الكيبورد)
            if(n_bytes > 1) {
                should_log = 1;
            }
        }

     if(should_log) {
            // 1. Immediate Printing (Phase 3.1)
          printf("\n[AUDIT] PID:%d UID:%d Trap:%s PC:0x%lx\n", 
          p->pid, p->uid, name, current_pc);

           // 2. Store in Ring Buffer (Phase 3.2)
          struct audit_record *ar = &audit_log[audit_head];

          ar->pid = p->pid;
          ar->uid = p->uid;
          ar->ticks = ticks;                    // Current system time (in ticks)

          // Copy syscall name to the buffer
          safestrcpy(ar->syscall_name, name, sizeof(ar->syscall_name));

          // Move the head pointer (circular buffer)
          audit_head = (audit_head + 1) % AUDIT_BUF_SIZE;
        }
    }
    // --------------------------------------------
    // -------------------------------
    // ------------------------------------------------------------
    // ------------------------------------------------------------



    // an interrupt will change sepc, scause, and sstatus,

    // so enable only now that we're done with those registers.

    intr_on();



    syscall();

  } else if((which_dev = devintr()) != 0){

    // ok

  } else if((r_scause() == 15 || r_scause() == 13) &&

            vmfault(p->pagetable, r_stval(), (r_scause() == 13)? 1 : 0) != 0) {

    // page fault on lazily-allocated page

  } else {

    printf("usertrap(): unexpected scause 0x%lx pid=%d\n", r_scause(), p->pid);

    printf("            sepc=0x%lx stval=0x%lx\n", r_sepc(), r_stval());

    setkilled(p);

  }



  if(killed(p))

    kexit(-1);



  // give up the CPU if this is a timer interrupt.

  if(which_dev == 2)

    yield();

 prepare_return();



  // the user page table to switch to, for trampoline.S

  uint64 satp = MAKE_SATP(p->pagetable);



  // return to trampoline.S; satp value in a0.

    return satp;

}











//
// set up trapframe and control registers for a return to user space
//
void
prepare_return(void)
{
  struct proc *p = myproc();

  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(). because a trap from kernel
  // code to usertrap would be a disaster, turn off interrupts.
  intr_off();

  // send syscalls, interrupts, and exceptions to uservec in trampoline.S
  uint64 trampoline_uservec = TRAMPOLINE + (uservec - trampoline);
  w_stvec(trampoline_uservec);

  // set up trapframe values that uservec will need when
  // the process next traps into the kernel.
  p->trapframe->kernel_satp = r_satp();         // kernel page table
  p->trapframe->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(p->trapframe->epc);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    // interrupt or trap from an unknown source
    printf("scause=0x%lx sepc=0x%lx stval=0x%lx\n", scause, r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  if(cpuid() == 0){
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
  }

  // ask for the next timer interrupt. this also clears
  // the interrupt request. 1000000 is about a tenth
  // of a second.
  w_stimecmp(r_time() + 1000000);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if(scause == 0x8000000000000009L){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000005L){
    // timer interrupt.
    clockintr();
    return 2;
  } else {
    return 0;
  }
}







// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}
