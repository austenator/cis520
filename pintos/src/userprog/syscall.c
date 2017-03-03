#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	//3-3 from ppt - not sure if need or what it does
	//lock_init(&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

  typedef int syscall_function (int, int, int);

  /* A system call. */   
  struct syscall     
  {       
	size_t arg_cnt;           
	/* Number of arguments. */       
	syscall_function *func;   
	/* Implementation. */     
	};   
	/* Table of system calls. */   
	static const struct syscall syscall_table[] =     
	{       
		{0, (syscall_function *) sys_halt},       
		{1, (syscall_function *) sys_exit},       
		{1, (syscall_function *) sys_exec},       
		{1, (syscall_function *) sys_wait},       
		{2, (syscall_function *) sys_create},       
		{1, (syscall_function *) sys_remove},       
		{1, (syscall_function *) sys_open},
		// need to put the rest in
		//{x, (syscall_function *) sys_filesize},
		//{x, (syscall_function *) sys_read},
		//{x, (syscall_function *) sys_write},
		//{x, (syscall_function *) sys_seek},
		//{x, (syscall_function *) sys_tell},
		//{x, (syscall_function *) sys_close}
	}

	const struct syscall *sc;   
	unsigned call_nr;   
	int args[3];   

	/* Get the system call. */   
	copy_in (&call_nr, f->esp, sizeof call_nr);   
	if (call_nr >= sizeof syscall_table / sizeof *syscall_table)     
	thread_exit ();   
	sc = syscall_table + call_nr;  

	/* Get the system call arguments. */   
	ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);   
	memset (args, 0, sizeof args);   
	copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);   
	/* Execute the system call,      and set the return value. */   
	f->eax = sc->func (args[0], args[1], args[2]);
  }
  //thread_exit ();
}
