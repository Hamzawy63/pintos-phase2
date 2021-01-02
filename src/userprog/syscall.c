#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static struct lock files_sys_lock;               /* lock for syschronization between files */

static void syscall_handler (struct intr_frame *);

void halt_wrapper(void* esp);
void exit_wrapper(void* esp);
int exec_wrapper(void* esp);
int wait_wrapper(void* esp);
void create_wrapper(void* esp);
void remove_wrapper(void* esp);
void open_wrapper(void* esp);
void filesize_wrapper(void* esp);
void read_wrapper(void* esp);
void write_wrapper(void* esp);
void seek_wrapper(void* esp);
void tell_wrapper(void* esp);
void close_wrapper(void* esp);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&files_sys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  void* esp = &f->esp;

  switch (get_int(esp))
  {
  case SYS_HALT:
    printf("(halt) begin\n");
    halt_wrapper(esp);
    break;
  
  case SYS_EXIT:
    exit_wrapper(esp);
    break;

  case SYS_EXEC:
    f->eax = exec_wrapper(esp);
    break;

  case SYS_WAIT:
    f->eax = wait_wrapper(esp);
    break;

  case SYS_CREATE:
    create_wrapper(esp);
    break;

  case SYS_REMOVE:
    remove_wrapper(esp);
    break;

  case SYS_OPEN:
    open_wrapper(esp);
    break;

  case SYS_FILESIZE:
    filesize_wrapper(esp);
    break;

  case SYS_READ:
    read_wrapper(esp);
    break;

  case SYS_WRITE:
    write_wrapper(esp);
    break;

  case SYS_SEEK:
    seek_wrapper(esp);
    break;

  case SYS_TELL:
    tell_wrapper(esp);
    break;

  case SYS_CLOSE:
    close_wrapper(esp);
    break;

  default:
    // negative area
    break;
  }

}

int 
get_int(int** esp)
{
  validate_void_ptr(*esp);
  int res = **esp;
  (*esp)++;
  return res;
}

char* 
get_char_ptr(char*** esp) 
{
  validate_void_ptr(**esp);
  char* res = **esp;
  (*esp)++;
  return res;
}

void* 
get_void_ptr(void*** esp)
{
  validate_void_ptr(**esp);
  void* res = **esp;
  (*esp)++;
  return res;
}

void 
validate_void_ptr(const void* pt)
{
  if (pt == NULL || !is_user_vaddr(pt) || !pagedir_get_page(thread_current()->pagedir, pt)) 
  {
    exit(-1);
  }
}

void
halt()
{
  shutdown_power_off();
}

void
halt_wrapper(void* esp)
{
  halt();
}

void
exit(int status)
{
  thread_exit();
}

void
exit_wrapper(void* esp)
{
  exit(get_int(esp));
}

int
exec(char* file_name)
{
  return process_execute(file_name);
}

int
exec_wrapper(void* esp)
{ 
  char* file_name = get_char_ptr(esp);
  return exec(file_name);
}

int
wait(int pid)
{
  return process_wait(pid);
}

int
wait_wrapper(void* esp)
{
  return wait(get_int(esp));
}

void
create()
{

}

void
create_wrapper(void* esp)
{
  char* file_name = get_char_ptr(esp);
}

void
remove()
{

}

void
remove_wrapper(void* esp)
{
  
}

void
open()
{
  exit(-1);
}

void
open_wrapper(void* esp)
{
  
}

void
filesize()
{

}

void
filesize_wrapper(void* esp)
{
  
}

void
read()
{

}

void
read_wrapper(void* esp)
{
  
}

void
write()
{

}

void
write_wrapper(void* esp)
{
  
}

void
seek()
{

}

void
seek_wrapper(void* esp)
{
  
}

void
tell()
{

}

void
tell_wrapper(void* esp)
{
  
}

void
close()
{

}

void
close_wrapper(void* esp)
{
  
}