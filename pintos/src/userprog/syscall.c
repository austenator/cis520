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


//
#define USER_VADDR_BOTTOM ((void *) 0x08048000 //taken from memory layout description in proj2.pdf
#define CLOSE_ALL -1
static void syscall_handler (struct intr_frame *);

void sys_halt (void);
void sys_exit (int status);
int sys_exec (const char *cmd_line);
int sys_wait (int pid);
int sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
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
{ //code for this method came from slides
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

}

void copy_in (void *dest UNUSED, void *src UNUSED, size_t size UNUSED) 
{ //src points to the stack, size = 4*(#arguments we are copying)
	int i;
	int *ptr;
	for (i = 0; i<(size/4); i++) { //divide by 4 because i goes by 4 bytes since its an integer
		ptr = (int *) src + i; //ptr now points to stack, we save it in ptr so we can run checks if it is valid
		if (!is_user_vaddr(ptr)|| ptr < (int *)USER_VADDR_BOTTOM)) { // bad/invalid ptr check
			sys_exit(-1);
		}
		if (!pagedir_get_page(thread_current()->pagedir, ptr)) { // bad/invalid ptr check
			sys_exit(-1);
		}
		((int *)dest)[i] = *ptr; //here is where the actual copying from stack to kernel space happens
	}
}

void sys_halt (void) {
	shutdown_power_off();
}
void sys_exit (int status) {
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_current()->wait_status->exit_code = status; //set my exit code then exit
	thread_exit();
}
int sys_exec (const char *cmd_line) {
	if (!is_user_vaddr(cmd_line)|| cmd_line < (int *)USER_VADDR_BOTTOM)) {
			sys_exit(-1);
		}	
	if (!pagedir_get_page(thread_current()->pagedir, cmd_line))   //more bad ptr checks
	{
			sys_exit(-1);
	}
	pid_t pid = process_execute(cmd_line); //execute process
	struct thread *cur = thread_current();
	struct list_elem *e;
	struct wait_status *w;
	for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) 
	{ //find the child process that we just created
		w = list_entry(e, struct wait_status, elem);
		if (w->tid==pid)
		{
			sema_down(&w->loaded); //block until child has fully loaded, then check successful_load
			if (!w->successful_load) //if not successful load, return -1 instead of its tid
			{
				pid = -1;
			}
			break;
		}
	}
	return pid;
}
int sys_wait (int pid UNUSED) {
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
bool sys_remove (const char *file) {
	lock_acquire(&fs_lock);
  	bool success = filesys_remove(file);
  	lock_release(&fs_lock);
  	return success;
}
int sys_open (const char *file) {
	if (!is_user_vaddr(file)|| file < (int *)USER_VADDR_BOTTOM))
	{
			sys_exit(-1);
	}	
	if (!pagedir_get_page(thread_current()->pagedir ,file)) 
	{
		sys_exit(-1);
	}
	lock_acquire(&fs_lock);
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

int sys_read (int fd, void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer)|| buffer < (int *)USER_VADDR_BOTTOM)) 
	{
			sys_exit(-1);
	}
	if (!pagedir_get_page(thread_current()->pagedir, buffer))
	{
			sys_exit(-1);
	}
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
		putbuf(buffer, length);
		return length;
	}
	
	if (!is_user_vaddr(buffer)|| buffer < (int *)USER_VADDR_BOTTOM)) 
	{
		sys_exit(-1);
	}
	if (!pagedir_get_page(thread_current()->pagedir, buffer))
	{
			sys_exit(-1);
	}

	lock_acquire(&fs_lock);

	struct file *f = get_file(fd);
	if (!f) {
		lock_release(&fs_lock);
		return -1;
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
	
	struct thread *curr_thread = thread_current();
	struct list_elem *curr_elem;
	struct process_file *pf;

	for(curr_elem = list_begin(&curr_thread->list_open_files); curr_elem != list_end (&curr_thread->list_open_files); curr_elem = list_next(curr_elem))
	{
		pf = list_entry(curr_elem, struct process_file, elem);
		if (fd == pf->fd || fd == CLOSE_ALL)
		{
			file_close(pf->file);
			list_remove(&pf->elem);
			free(pf);
			if (fd != CLOSE_ALL)
			{
				lock_release(&fs_lock);
				return;
			}
		}
	}
	
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












