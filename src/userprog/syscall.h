#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/palloc.h"

#include "threads/synch.h"

typedef int pid_t;


static void syscall_handler (struct intr_frame *);
typedef void (*CALL_PROC)(struct intr_frame*);
void IWrite(struct intr_frame*);
void IExit(struct intr_frame *f);
void ICreate(struct intr_frame *f);
void IOpen(struct intr_frame *f);
void IClose(struct intr_frame *f);
void IRead(struct intr_frame *f);
void IFileSize(struct intr_frame *f);
void IExec(struct intr_frame *f);
void IWait(struct intr_frame *f);
void ISeek(struct intr_frame *f);
void IRemove(struct intr_frame *f);
void ITell(struct intr_frame *f);
void IHalt(struct intr_frame *f);


void is_valid_addr (const void *addr);
void is_valid_buffer (void *buffer, unsigned size);

struct file_node *get_node (int fd);
pid_t exec (const char *cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void exit (int status);
void syscall_init (void);

#endif /* userprog/syscall.h */
