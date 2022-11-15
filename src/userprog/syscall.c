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
void write (struct intr_frame *f, int fd, const void *buffer, unsigned size);
void read (struct intr_frame *f, int fd, const void *buffer, unsigned size);
void create (struct intr_frame *f, const char *file, unsigned initial_size);
void seek (int fd, unsigned position);
void valid_ptr (const void *pointer);
void call_with_2 (struct intr_frame *f, void *esp, int call);
void call_with_3 (struct intr_frame *f, void *esp, int call);
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

struct thread* get_child(tid_t tid, struct list *threads)
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

void call_with_2 (struct intr_frame *f, void *esp, int call)
{
  int argv = *((int*) esp);
  esp += 4;
  int arg1 = *((int*) esp);
  esp += 4;

  if (call == SYS_CREATE)
  {
    valid_ptr((const void *) argv);
    create(f, (const char *) argv, (unsigned) arg1);
  }
  else if (call == SYS_SEEK)
  {
    seek(argv, (unsigned) arg1);
  }
}

void call_with_3 (struct intr_frame *f, void *esp, int call)
{
  int argv = *((int*) esp);
  esp += 4;
  int arg1 = *((int*) esp);
  esp += 4;
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
read (struct intr_frame *f, int fd, const void *buffer, unsigned size)
{
  if (fd == 0)
    f->eax = input_getc ();
  else
    exit (-1);
}

void
write (struct intr_frame *f, int fd, const void *buffer, unsigned size)
{
  uint8_t *buff = (uint8_t *) buffer;
  if (fd == 1)
  {
    putbuf ((char *)buff, size);
    f->eax = (int)size;
  }
  else
    exit(-1);
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
  esp += 1;
  valid_ptr ((const void *) esp);
  if (number == SYS_HALT) {
    shutdown_power_off();
  }
  else if (number == SYS_EXIT) {
    exit (*esp);
  }
  else if (number == SYS_READ) {
    call_with_3 (f, esp, SYS_READ);
  }
  else if (number == SYS_WRITE) {
    call_with_3 (f, esp, SYS_WRITE);
  }
  else if (number == SYS_CREATE) {
    call_with_2(f, esp, SYS_CREATE);
  }
  else if (number == SYS_SEEK) {
    call_with_2(f, esp, SYS_SEEK);
  }
  else {
    shutdown_power_off ();
  }
}
