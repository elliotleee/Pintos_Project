#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

typedef int pid_t;


void exit (int status);
void syscall_init (void);

#endif /* userprog/syscall.h */
