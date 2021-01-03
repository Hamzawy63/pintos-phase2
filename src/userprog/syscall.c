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
bool create_wrapper(void* esp);
bool remove_wrapper(void* esp);
int open_wrapper(void* esp);
void filesize_wrapper(void* esp);
void read_wrapper(void* esp);
int write_wrapper(void* esp);
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

  void* esp = f->esp;
  
  switch (get_int(&esp))
  {
  case SYS_HALT:
    halt_wrapper(&esp);
    break;
  
  case SYS_EXIT:
    exit_wrapper(&esp);
    break;

  case SYS_EXEC:
    f->eax = exec_wrapper(&esp);
    break;

  case SYS_WAIT:
    f->eax = wait_wrapper(&esp);
    break;

  case SYS_CREATE:
    f->eax = create_wrapper(&esp);
    break;

  case SYS_REMOVE:
    f->eax = remove_wrapper(&esp);
    break;

  case SYS_OPEN:
    f->eax = open_wrapper(&esp);
    break;

  case SYS_FILESIZE:
    filesize_wrapper(&esp);
    break;

  case SYS_READ:
    read_wrapper(&esp);
    break;

  case SYS_WRITE:
    f->eax = write_wrapper(&esp);
    break;

  case SYS_SEEK:
    seek_wrapper(&esp);
    break;

  case SYS_TELL:
    tell_wrapper(&esp);
    break;

  case SYS_CLOSE:
    close_wrapper(&esp);
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
  (*esp)+=4;
  return **esp;
}

char* 
get_char_ptr(char*** esp) 
{
  validate_void_ptr(*esp);
  validate_void_ptr(**esp);
  char* res = **esp;
  (*esp)+=4;
  return res;
}

void* 
get_void_ptr(void*** esp)
{
  validate_void_ptr(*esp);
  validate_void_ptr(**esp);
  void* res = **esp;
  (*esp)+=4;
  return res;
}

void 
validate_void_ptr(const void* pt)
{
  if (pt == NULL || !is_user_vaddr(pt) || pagedir_get_page(thread_current()->pagedir, pt) == NULL) 
  {
    sys_exit(-1);
  }
}

void
sys_halt()
{
  shutdown_power_off();
}

void
halt_wrapper(void* esp)
{ 
  sys_halt();
}

void
sys_exit(int status)
{
  struct thread* parent = thread_current()->parent_thread;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if(parent) parent->child_status = status;
  thread_exit();
}

void
exit_wrapper(void* esp)
{
  sys_exit(get_int(esp));
}

int
sys_exec(char* file_name)
{
  return process_execute(file_name);
}

int
exec_wrapper(void* esp)
{ 
  char* file_name = get_char_ptr(esp);
  return sys_exec(file_name);
}

int
sys_wait(int pid)
{
  return process_wait(pid);
}

int
wait_wrapper(void* esp)
{
  return sys_wait(get_int(esp));
}

bool
sys_create(char* name, size_t size)
{
  bool res;
  lock_acquire(&files_sys_lock);

  res = filesys_create(name,size);

  lock_release(&files_sys_lock);
  return res;
}

bool
create_wrapper(void* esp)
{
  char* name = get_char_ptr(esp);
  size_t size = get_int(esp);

  return sys_create(name,size);
}

bool
sys_remove(char* name)
{
  bool res;
  lock_acquire(&files_sys_lock);

  res = filesys_remove(name);

  lock_release(&files_sys_lock);
  return res;
}

bool
remove_wrapper(void* esp)
{
  char* name = get_char_ptr(esp);

  return sys_remove;
}

int
sys_open(char* name)
{
  struct open_file* open = palloc_get_page(0);
  if (open == NULL) 
  {
    palloc_free_page(open);
    return -1;
  }
  lock_acquire(&files_sys_lock);
  open->ptr = filesys_open(name);
  lock_release(&files_sys_lock);
  if (open->ptr == NULL)
  {
    return -1;
  }
  open->fd = thread_current()->fd_last++;
  list_push_back(&thread_current()->open_file_list,&open->elem);
  return open->fd;
}

int
open_wrapper(void* esp)
{
  char* name = get_char_ptr(esp);

  return sys_open(name);
}

void
sys_filesize()
{

}

void
filesize_wrapper(void* esp)
{
  
}

void
sys_read()
{

}

void
read_wrapper(void* esp)
{
  
}

int
sys_write(int fd, void* buffer, int size)
{

  if (fd == 1)
  {
    
    lock_acquire(&files_sys_lock);
    putbuf(buffer,size);
    lock_release(&files_sys_lock);
    return size;

  } else {
    
    struct thread* t = thread_current();
    struct file* my_file = NULL;
    for (struct list_elem* e = list_begin (&t->open_file_list); e != list_end (&t->open_file_list);
    e = list_next (e))
    {
      struct open_file* opened_file = list_entry (e, struct open_file, elem);
      if (opened_file->fd == fd)
      {
        my_file = opened_file->ptr;
        break;
      }
    }

    if (my_file == NULL)
    {
      return -1;
    }
    int res;
    lock_acquire(&files_sys_lock);
    res = file_write(my_file,buffer,size);
    lock_release(&files_sys_lock);
    return res;
  }

}

int
write_wrapper(void* esp)
{
  int fd, size;
  void* buffer;
  fd = get_int(esp);
  size = get_int(esp);
  buffer = get_void_ptr(esp);
  
  return sys_write(fd,buffer,size);
}

void
sys_seek()
{

}

void
seek_wrapper(void* esp)
{
  
}

void
sys_tell()
{

}

void
tell_wrapper(void* esp)
{
  
}

void
sys_close()
{

}

void
close_wrapper(void* esp)
{
  
}
