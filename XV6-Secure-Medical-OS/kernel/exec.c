#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"
#include "fs.h"
#include "file.h"
#include "stat.h"


static int loadseg(pde_t *, uint64, struct inode *, uint, uint);

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  // 1. Get the inode of the program
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }

  // 2. Lock the inode for reading
  ilock(ip);

  // --- Requirement 2.3: Execute Permission Check (Security Enforcement) ---
  if(p->uid != 0){                    // Admin (UID 0) is always allowed
    int allowed = 0;

    if(p->uid == ip->uid){            // Current user is the file owner
      if(ip->mode & 0100)             // Owner execute bit
        allowed = 1;
    } 
    else {                            // Other users
      if(ip->mode & 0001)             // Others execute bit
        allowed = 1;
    }

    if(!allowed){
      iunlockput(ip);
      end_op();
      return -1;                      // Permission denied
    }
  }
  // -----------------------------------------------------------

  // 3. Read ELF header to verify it's a valid executable
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // Load program segments into memory
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;

    if(ph.type != ELF_PROG_LOAD)
      continue;

    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;

    uint64 sz1;
    if((sz1 = uvmalloc(pagetable, sz, ph.vaddr + ph.memsz, flags2perm(ph.flags))) == 0)
      goto bad;

    sz = sz1;
    if(loadseg(pagetable, ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }

  // Unlock inode after loading is complete
  iunlockput(ip);
  end_op();
  ip = 0;

  // Setup user stack
  sz = PGROUNDUP(sz);
  uint64 sz1;
  if((sz1 = uvmalloc(pagetable, sz, sz + (USERSTACK+1)*PGSIZE, PTE_W)) == 0)
    goto bad;
  sz = sz1;

  uvmclear(pagetable, sz - (USERSTACK+1)*PGSIZE);
  sp = sz;
  stackbase = sp - USERSTACK*PGSIZE;

  // Push arguments onto the stack
  for(argc = 0; argv[argc]; argc++){
    if(argc >= MAXARG)
      goto bad;

    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16;                    // RISC-V stack alignment
    if(sp < stackbase)
      goto bad;

    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;

    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;

  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  p->trapframe->a1 = sp;

  // Update process name
  for(last=s=path; *s; s++)
    if(*s == '/') last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));

  // Switch page tables and activate the new program
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  uint64 oldsz = p->sz;
  p->sz = sz;

  p->trapframe->epc = elf.entry;
  p->trapframe->sp = sp;

  proc_freepagetable(oldpagetable, oldsz);

  return argc;

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
} 




// Load an ELF program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
static int
loadseg(pagetable_t pagetable, uint64 va, struct inode *ip, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;

  for(i = 0; i < sz; i += PGSIZE){
    pa = walkaddr(pagetable, va + i);
    if(pa == 0)
      panic("loadseg: address should exist");
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, 0, (uint64)pa, offset+i, n) != n)
      return -1;
  }
  
  return 0;
}
