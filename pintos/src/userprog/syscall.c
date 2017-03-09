#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
//
#include <string.h>
#include <stdlib.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/init.h"
#include "list.h"
#include "process.h"
//needed to access all_list -not sure if should move all_list to .h file
//#include "threads/thread.c"


static void syscall_handler (struct intr_frame *);

void sys_halt (void);
void sys_exit (int status);
int sys_exec (const char *cmd_line);
int sys_wait (int pid);
int sys_create (const char *file, unsigned initial_size);
int sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize(int fd);
int sys_read(int td, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned length);
int sys_seek(int fd, unsigned pos);
int sys_tell(int fd);
int sys_close(int fd);
void copy_in (void *dest, void *src, size_t size);

struct lock fs_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");

  typedef int syscall_function (int, int, int);

  /* A system call. */   
  struct syscall     
  {       
		size_t arg_cnt;           /* Number of arguments. */       
		syscall_function *func;   /* Implementation. */     
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
		{1, (syscall_function *) sys_filesize},
		{3, (syscall_function *) sys_read},
		{3, (syscall_function *) sys_write},
		{2, (syscall_function *) sys_seek},
		{1, (syscall_function *) sys_tell},
		{1, (syscall_function *) sys_close}
	};

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
  //}
  //thread_exit ();
}

void copy_in (void *dest UNUSED, void *src UNUSED, size_t size UNUSED) {
	//*(char *)dest = *(char *)src;
	int i;
	int *ptr;
	for (i = 0; i<(size/4); i++) {
		ptr = (int *) src + i;
		if (!is_user_vaddr(ptr)) {
			//call sys_exit(ERROR) ? instead of thread_exit()?
			printf("not in user space!\n");
			thread_exit();
		}
		((int *)dest)[i] = *ptr;
	}
}

void sys_halt (void) {
	shutdown_power_off();
}
void sys_exit (int status) {
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_current()->wait_status->exit_code = 0;
	thread_exit();
}
int sys_exec (const char *cmd_line) {
	pid_t pid = process_execute(cmd_line);
	//add newly created thread/process to my list of children
	//struct list_elem *e;
	//struct thread *t;
	//struct thread *cur = thread_current();
	//for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next(e))
	//{
	//	t = list_entry(e, struct thread, allelem);
	//	if (t->wait_status->tid == pid)
	//	{
	//		list_push_back(&cur->children, &t->wait_status->elem);
	//		break;
	//	}
	//} //do all this in process_execute?
	//list_push_back(&thread_current()->children, &LISTELEM);
	return pid;
}
int sys_wait (int pid UNUSED) {
	//return 0;
	return process_wait(pid);
}
int sys_create (const char *file UNUSED, unsigned initial_size UNUSED) {
	return 0;
}
int sys_remove (const char *file UNUSED) {
	return 0;
}
int sys_open (const char *file UNUSED) {
	return 0;
}
int sys_filesize(int fd UNUSED) {
	return 0;
}
int sys_read(int td UNUSED, void *buffer UNUSED, unsigned size UNUSED) {
	return 0;
}
int sys_write(int fd UNUSED, const void *buffer UNUSED, unsigned length UNUSED) {
	//return 0;
	//putbuf(buffer, length);
	//return length;
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, length); //TODO: need to valid check all spots in buffer...
		return length;
	}
	/*lock_acquire(&fs_lock);
	struct file *f = //find file
	if (!f) {
		lock_release(&fs_lock);
		return ERROR;
	}
	int bytes = file_write(f, buffer, length);
	lock_release(&fs_lock);
	return bytes;*/
	//temp
	return length;
	
}
int sys_seek(int fd UNUSED, unsigned pos UNUSED) {
	return 0;
}
int sys_tell(int fd UNUSED) {
	return 0;
}
int sys_close(int fd UNUSED) {
	return 0;
}




