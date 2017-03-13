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
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "pagedir.h"
//needed to access all_list -not sure if should move all_list to .h file
//#include "threads/thread.c"

//3-10
#define USER_VADDR_BOTTOM ((void *) 0x08048000 //taken from memory layout description in proj2.pdf
#define CLOSE_ALL -1
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
void sys_seek(int fd, unsigned pos);
unsigned sys_tell(int fd);
void sys_close(int fd);
void copy_in (void *dest, void *src, size_t size);
struct file* get_file(int fd);

struct lock fs_lock;

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

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
		if (!is_user_vaddr(ptr)|| ptr < (int *)USER_VADDR_BOTTOM)) {
			//call sys_exit(ERROR) ? instead of thread_exit()?
			//printf("not in user space!\n");
			//thread_exit();
			sys_exit(-1);
		}
		if (!pagedir_get_page(thread_current()->pagedir, ptr)) {
			sys_exit(-1);
		}
		((int *)dest)[i] = *ptr;
	}
}

void sys_halt (void) {
	shutdown_power_off();
}
void sys_exit (int status) {
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_current()->wait_status->exit_code = status; //3-10 check this is correct
	thread_exit();
}
int sys_exec (const char *cmd_line) {
	if (!pagedir_get_page(thread_current()->pagedir, cmd_line))
	{
			sys_exit(-1);
	}
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
int sys_create (const char *file, unsigned initial_size) {
	lock_acquire(&fs_lock);
	if (!pagedir_get_page(thread_current()->pagedir ,file)) 
	{
		sys_exit(-1);
	}
	bool result = filesys_create(file, initial_size);
	lock_release(&fs_lock);
	return result;
}
int sys_remove (const char *file UNUSED) {
	return 0;
}
int sys_open (const char *file) {
	lock_acquire(&fs_lock);
	if (!pagedir_get_page(thread_current()->pagedir ,file)) 
	{
		sys_exit(-1);
	}
	struct file *f = filesys_open(file);
	
	if(!f)
	{
		lock_release(&fs_lock);
		return -1;
	}
	
	// Add process_file struct to current thread's list of open files.
	struct process_file *pf = malloc(sizeof(struct process_file));

	// Set the process file property to the file we opened earlier.
	pf->file = f;
	pf->fd = thread_current()->fd;

	// Increment the current thread's fd number for the next.
	thread_current()->fd++;

	// Puts process file struct on the current thread's list of open files. 
  	list_push_back(&thread_current()->list_open_files, &pf->elem);

	lock_release(&fs_lock);

	// Return the file descriptor to the user. 
  	return pf->fd;
	
}
int sys_filesize(int fd UNUSED) {
	lock_acquire(&fs_lock);
	struct file *f = get_file(fd);
	off_t length = file_length(f);
	lock_release(&fs_lock);
	return length;
}
//int sys_read(int td UNUSED, void *buffer UNUSED, unsigned size UNUSED) {
//	return 0;
//}


int sys_read (int fd, void *buffer, unsigned size)
{
  if (fd == 0)
    {
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
	{
	  local_buffer[i] = input_getc();
	}
      return size;
    }
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  if (!f )
    {
      lock_release(&fs_lock);
      return -1;
    }
  int bytes = file_read(f, buffer, size);
  lock_release(&fs_lock);
  return bytes;
}

int sys_write(int fd, const void *buffer, unsigned length) {
	
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, length); //TODO: need to valid check all spots in buffer...
		return length;
	}
	
	lock_acquire(&fs_lock);

	struct file *f = get_file(fd);
	if (!f) {
		lock_release(&fs_lock);
		return -1;
	}
	if (!pagedir_get_page(thread_current()->pagedir, buffer))
	{
			sys_exit(-1);
	}
	int bytes = file_write(f, buffer, length);
	lock_release(&fs_lock);
	return bytes;
	
}
void sys_seek(int fd, unsigned pos) {
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  if (!f)
    {
      lock_release(&fs_lock);
      return;
    }
  file_seek(f, pos);
  lock_release(&fs_lock);
}

unsigned sys_tell(int fd) {
  lock_acquire(&fs_lock);
  struct file *f = get_file(fd);
  if (!f)
    {
      lock_release(&fs_lock);
      return -1;
    }
  off_t position = file_tell(f);
  lock_release(&fs_lock);
  return position;
}
void sys_close(int fd) {
	lock_acquire(&fs_lock);
	
	//struct thread *curr_thread = thread_current();
	//struct list_elem *curr_elem;// = list_begin(&curr_thread->list_open_files);
	//struct process_file *pf;
	
	//struct thread *t = thread_current();
  	//struct list_elem *next, *e = list_begin(&t->list_open_files);
/*
  while (e != list_end (&t->list_open_files))
    {
      next = list_next(e);
      struct process_file *pf = list_entry (e, struct process_file, elem);
      if (fd == pf->fd || fd == CLOSE_ALL)
	{
	  file_close(pf->file);
	  list_remove(&pf->elem);
	  free(pf);
	  if (fd != CLOSE_ALL)
	    {
	      return;
	    }
	}
      e = next;
    }*/



	/*for(curr_elem = list_begin(&curr_thread->list_open_files); curr_elem != list_end (&curr_thread->list_open_files); curr_elem = list_next(curr_elem)){
		pf = list_entry(curr_elem, struct process_file, elem);
		if (fd == pf->fd || fd == CLOSE_ALL)
		{
			file_close(pf->file);
			list_remove(&pf->elem);
			free(pf);
			if (fd != CLOSE_ALL){
				return;
			}
		}
	}*/
	
	lock_release(&fs_lock);
}

struct file* get_file(int fd){
	struct thread *t = thread_current();
	struct list_elem *e;
	
	for (e = list_begin (&t->list_open_files); e != list_end (&t->list_open_files); e = list_next (e))       
        {
          struct process_file *process_file = list_entry (e, struct process_file, elem);

          if (fd == process_file->fd)
	  {
	      return process_file->file;
	  }
        }
  return NULL;
}












