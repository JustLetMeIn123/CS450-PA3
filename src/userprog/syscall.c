#include "userprog/syscall.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
void exit (int status);
void create (struct intr_frame *f, const char *file, unsigned initial_size);
void seek (int fd, unsigned position);
void write (struct intr_frame *f, int fd, void *buffer, unsigned size);
void read (struct intr_frame *f, int fd, void *buffer, unsigned size);
void valid_ptr (const void *pointer);
void callArgs (struct intr_frame *f, void *esp, int call);
int open (const char *file);
int remove (const char *file);
int filesize (int fd);
int tell (int fd);
int close (int fd);
struct file_info* get_file (int fd);
struct lock f_lock;


void valid_ptr (const void *pointer)
{
  if (!is_user_vaddr(pointer))
    exit(-1);

  void *check = pagedir_get_page(thread_current()->pagedir, pointer);
  if (check == NULL)
    exit(-1);
}

struct thread* get_child (tid_t tid, struct list *threads)
{
  if (!is_user_vaddr ((const void*) threads))
    return NULL;
  struct list_elem *e;
  for (e = list_begin (threads); e != list_end (threads); e = list_next (e))
  {
    struct thread* child = list_entry (e, struct thread, child_elem);
    
    if(child->tid == tid)
      return child;
  }
  return NULL;
}

struct file_info* get_file (int fd)
{
  struct list_elem *e;
  for (e = list_begin (&thread_current() -> files); e != list_end (&thread_current() -> files);
       e = list_next (e))
  {
    struct file_info *elem = list_entry (e, struct file_info, file_elem);
    if(elem -> fd == fd)
      return elem;
    }
  return NULL;
}

void callArgs (struct intr_frame *f, void *esp, int call) {
  int argv = *((int*) esp);
  esp += 4;

  if (call == SYS_EXIT)
  {
    exit(argv);
    return;
  }
  else if (call == SYS_EXEC)
  {
    valid_ptr((const void*) argv);
    f -> eax = process_execute((const char *)argv);
    return;
  }
  else if (call == SYS_WAIT)
  {
    f -> eax = process_wait(argv);
    return;
  }
  else if (call == SYS_REMOVE)
  {
    valid_ptr((const void*) argv);
    f -> eax = remove((const char *) argv);
    return;
  }
  else if(call == SYS_OPEN)
  {
    valid_ptr((const void*) argv);
    f -> eax = open((const char *) argv);
    return;
  }
  else if (call == SYS_FILESIZE)
  {
    f -> eax = filesize(argv);
    return;
  }
  else if (call == SYS_TELL)
  {
    f -> eax = tell(argv);
    return;
  }
  else if (call == SYS_CLOSE)
  {
    close(argv);
    return;
  }
  
  int arg1 = *((int*) esp);
  esp += 4;
  
  if (call == SYS_CREATE)
  {
    valid_ptr((const void *) argv);
    create(f, (const char *) argv, (unsigned) arg1);
    return;
  }
  else if (call == SYS_SEEK)
  {
    seek(argv, (unsigned) arg1);
    return;
  }

  int arg2 = *((int*) esp);
  esp += 4;

  valid_ptr ((const void *) arg1);
  if (call == SYS_WRITE)
    write (f, argv, (void *) arg1, (unsigned) arg2);
  else
    read (f, argv, (void *) arg1, (unsigned) arg2);

}

void exit (int status)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct thread *child = NULL;
  for (e = list_begin (&cur->parent->children); e != list_end (&cur->parent->children); e = list_next (e))
  {
    struct thread *c = list_entry (e, struct thread, child_elem);
    
    if(c->tid == cur->tid)
      child = c;
  }
  if (child != NULL)
    child -> parent -> exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  //sema_up (&mutex);
  sema_up (&cur -> l_lock);
  thread_exit ();
}

void
create (struct intr_frame *f, const char *file, unsigned initial_size)
{
  lock_acquire(&f_lock);
  f->eax = filesys_create(file, initial_size);
  lock_release(&f_lock);
}

void
seek (int fd, unsigned position)
{
  struct file_info *file_elem = get_file(fd);
  if (file_elem == NULL) 
  {
    return;
  }

  struct file *this_file = file_elem->this_file;
  lock_acquire(&f_lock);
  file_seek(this_file, position);
  lock_release(&f_lock);
}

void
read (struct intr_frame *f, int fd, void *buffer, unsigned size)
{
  if (fd == 0)
    f->eax = input_getc ();
  else if (fd > 0)
  {
    struct file_info *fileI = get_file (fd);
    if (fileI == NULL || buffer == NULL)
    {
      f->eax = -1;
      return;
    }
    struct file *thisFile = fileI->this_file;
    lock_acquire (&f_lock);
    int val = file_read (thisFile, buffer, size);
    f->eax = val;
    lock_release (&f_lock);
    if(val < (int)size && val != 0)
    {
      f->eax = -1;
      return;
    }
  }
  else
    exit (-1);
}

void
write (struct intr_frame *f, int fd, void *buffer, unsigned size)
{
  uint8_t *buff = (uint8_t *) buffer;
  if (fd == 1)
  {
    putbuf ((char *)buff, size);
    f->eax = (int)size;
  }
  else
  {
    struct file_info *fileI = get_file (fd);
    if (fileI == NULL || buffer == NULL)
    {
      f->eax = -1;
      return;
    }
    struct file *thisFile = fileI->this_file;
    lock_acquire (&f_lock);
    int val = file_write (thisFile, buffer, size);
    f->eax = val;
    lock_release (&f_lock);
  }
}

int remove (const char *file)
{
  lock_acquire(&f_lock);
  bool val = filesys_remove(file);
  lock_release(&f_lock);
  if (val == true) {
    return 1;
  } 
  return 0;
}

int open (const char *file)
{
  int ret = -1;
  lock_acquire(&f_lock);
  struct thread *current = thread_current ();
  struct file * open_file = filesys_open(file);
  lock_release(&f_lock);
  if(open_file != NULL)
  {
    current->file_size = current->file_size + 1;
    ret = current->file_size;
    struct file_info *fd_elem = (struct file_info*) malloc(sizeof(struct file_info));
    fd_elem->fd = ret;
    fd_elem->this_file = open_file;
    list_push_back(&current->files, &fd_elem->file_elem);
  }
  return ret;
}

int filesize (int fd)
{
  struct file *thisfile = get_file(fd)->this_file;
  lock_acquire(&f_lock);
  int val = file_length(thisfile);
  lock_release(&f_lock);
  return val;
}

int tell (int fd)
{
  struct file_info *fd_elem = get_file(fd);
  if(fd_elem == NULL)
  {
    return -1;
  }
  struct file *thisfile = fd_elem->this_file;
  lock_acquire(&f_lock);
  unsigned val = file_tell(thisfile);
  lock_release(&f_lock);
  return val;
}

int close (int fd)
{
  struct file_info *fd_elem = get_file(fd);
  if(fd_elem == NULL)
  {
    return 0;
  }
  struct file *thisfile = fd_elem->this_file;
  lock_acquire(&f_lock);
  file_close(thisfile);
  lock_release(&f_lock);
  return 1;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&f_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *esp = f->esp;
  valid_ptr ((const void *) esp);
  int number = *esp;
  //printf ("Call: %d\n", number);
  esp += 1;
  valid_ptr ((const void *) esp);
  if (number == SYS_HALT) {
    shutdown_power_off();
  }
  else if (number == SYS_READ) {
    callArgs(f, esp, SYS_READ);
  }
  else if (number == SYS_WRITE) {
    callArgs(f, esp, SYS_WRITE);
  } 
  else if (number == SYS_EXIT) {
    callArgs(f, esp, SYS_EXIT);
  } 
  else if (number == SYS_EXEC) {
    callArgs(f, esp, SYS_EXEC);
  } 
  else if (number == SYS_WAIT) {
    callArgs(f, esp, SYS_WAIT);
  } 
  else if (number == SYS_REMOVE) {
    callArgs(f, esp, SYS_REMOVE);
  } 
  else if (number == SYS_OPEN) {
    callArgs(f, esp, SYS_OPEN);
  } 
  else if (number == SYS_FILESIZE) {
    callArgs(f, esp, SYS_FILESIZE);
  } 
  else if (number == SYS_TELL) {
    callArgs(f, esp, SYS_TELL);
  } else if(number == SYS_CLOSE) {
    callArgs(f, esp, SYS_CLOSE);
  }
  else if (number == SYS_CREATE) {
    callArgs(f, esp, SYS_CREATE);
  }
  else if (number == SYS_SEEK) {
    callArgs(f, esp, SYS_SEEK);
  }
  else {
    shutdown_power_off ();
  }
}
