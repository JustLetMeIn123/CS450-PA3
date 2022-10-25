#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);
struct thread* get_child(tid_t tid, struct list *threads);

#endif /* userprog/syscall.h */
