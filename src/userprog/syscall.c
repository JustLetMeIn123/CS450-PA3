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
void call_with_2 (struct intr_frame *f, void *esp, int call);
void call_with_3 (struct intr_frame *f, void *esp, int call);
void call_with_1 (struct intr_frame *f, int choose, void *esp);
int open (const char *file);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
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

void call_with_1 (struct intr_frame *f, int choose, void *esp)
{
  int argv = *((int*) esp);
  esp += 4;

  if (choose == SYS_EXIT)
  {
    exit(argv);
  }
  else if (choose == SYS_EXEC)
  {
    valid_ptr((const void*) argv);
    f -> eax = exec((const char *)argv);
  }
  else if (choose == SYS_WAIT)
  {
    f -> eax = wait(argv);
  }
  else if (choose == SYS_REMOVE)
  {
    valid_ptr((const void*) argv);
    f -> eax = remove((const char *) argv);
  }
  else if(choose == SYS_OPEN)
  {
    valid_ptr((const void*) argv);
    f -> eax = open((const char *) argv);
  }
  else if (choose == SYS_FILESIZE)
  {
    f -> eax = filesize(argv);
  }
  else if (choose == SYS_TELL)
  {
    f -> eax = tell(argv);
  }
  else if (choose == SYS_CLOSE)
  {
    close(argv);
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

tid_t
exec (const char *cmd_line)
{
  struct thread* parent = thread_current();
  tid_t pid = -1;
  pid = process_execute(cmd_line);
  //printf ("after process_execute is called\n");
  struct thread *child = get_child(pid, &parent -> children);
  //sema_down (&child->c_lock);
  //printf ("%s\n", child->name);
  if(child -> status != THREAD_READY)
  {
    return -1;
  }
  return pid;
}

int wait (tid_t pid)
{
  return process_wait(pid);
}

int remove (const char *file)
{
  lock_acquire(&f_lock);
  bool ret = filesys_remove(file);
  lock_release(&f_lock);
  if (ret == true) {
    return 1;
  } 
  return 0;
}

int open (const char *file)
{
  int ret = -1;
  lock_acquire(&f_lock);
  struct thread *cur = thread_current ();
  struct file * opened_file = filesys_open(file);
  lock_release(&f_lock);
  if(opened_file != NULL)
  {
    cur->file_size = cur->file_size + 1;
    ret = cur->file_size;
    /*create and init new fd_element*/
    struct file_info *file_d = (struct file_info*) malloc(sizeof(struct file_info));
    file_d->fd = ret;
    file_d->this_file = opened_file;
    // add this fd_element to this thread fd_list
    list_push_back(&cur->files, &file_d->file_elem);
  }
  return ret;
}

int filesize (int fd)
{
  struct file *myfile = get_file(fd)->this_file;
  lock_acquire(&f_lock);
  int ret = file_length(myfile);
  lock_release(&f_lock);
  return ret;
}

int tell (int fd)
{
  struct file_info *fd_elem = get_file(fd);
  if(fd_elem == NULL)
  {
    return -1;
  }
  struct file *myfile = fd_elem->this_file;
  lock_acquire(&f_lock);
  unsigned ret = file_tell(myfile);
  lock_release(&f_lock);
  return ret;
}

int close (int fd)
{
  struct file_info *fd_elem = get_file(fd);
  if(fd_elem == NULL)
  {
    return 0;
  }
  struct file *myfile = fd_elem->this_file;
  lock_acquire(&f_lock);
  file_close(myfile);
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
    call_with_3 (f, esp, SYS_READ);
  }
  else if (number == SYS_WRITE) {
    call_with_3 (f, esp, SYS_WRITE);
  } 
  else if (number == SYS_EXIT) {
    call_with_1(f, SYS_EXIT,esp);
  } 
  else if (number == SYS_EXEC) {
    call_with_1(f, SYS_EXEC,esp);
  } 
  else if (number == SYS_WAIT) {
    call_with_1(f, SYS_WAIT,esp);
  } 
  else if (number == SYS_REMOVE) {
    call_with_1(f, SYS_REMOVE,esp);
  } 
  else if (number == SYS_OPEN) {
    call_with_1(f, SYS_OPEN,esp);
  } 
  else if (number == SYS_FILESIZE) {
    call_with_1(f, SYS_FILESIZE,esp);
  } 
  else if (number == SYS_TELL) {
    call_with_1(f, SYS_TELL,esp);
  } else if(number == SYS_CLOSE) {
    call_with_1(f, SYS_CLOSE, esp);
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
