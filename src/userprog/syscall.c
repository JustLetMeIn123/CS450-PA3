#include "userprog/syscall.h"
#include <stdio.h>
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
void check_valid_ptr (const void *pointer);
struct thread* get_child(tid_t tid, struct list *threads);
void exit (int status);
void write (struct intr_frame *f, void *esp);

struct thread*
get_child(tid_t tid, struct list *threads)
{
  struct list_elem *e;
  for (e = list_begin (threads); e != list_end (threads); e = list_next (e))
  {
    struct thread* child = list_entry (e, struct thread, child_elem);
    if(child->tid == tid)
    {
      return child;
    }
  }
  return NULL;
}

void check_valid_ptr (const void *pointer)
{
    if (!is_user_vaddr(pointer))
    {
        exit(-1);
    }

    void *check = pagedir_get_page(thread_current()->pagedir, pointer);
    if (check == NULL)
    {
        exit(-1);
    }
}

void exit (int status)
{
  struct thread *cur = thread_current();
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  check_valid_ptr((const void*) f -> esp);
  int *esp = f->esp;
  int number = *esp;
  esp += 1;
  check_valid_ptr((const void*) esp);
  if (number == SYS_EXIT) {
    exit (*esp);
  }
  else if (number == SYS_READ) {
    printf ("Read\n");
  }
  else if (number == SYS_WRITE) {
    write (f, esp);
  }
  else {
    shutdown_power_off();
  }
}

void
write (struct intr_frame *f, void *esp)
{
  int argv = *((int*) esp);
  esp += 4;
  int argv_1 = *((int*) esp);
  esp += 4;
  int argv_2 = *((int*) esp);
  esp += 4;

  check_valid_ptr((const void*) argv_1);
  void *temp = ((void*) argv_1)+ argv_2 ;
  check_valid_ptr((const void*) temp);

  uint8_t * buffer = (uint8_t *) (void *) argv_1;
  if (argv == 1)
  {
    putbuf((char *)buffer, (unsigned) argv_2);
    f->eax = (int)(unsigned) argv_2;
  }
  else
  {
    exit(-1);
  }
}
