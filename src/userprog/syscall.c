#include "userprog/syscall.h"
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

CALL_PROC pfn[21];

struct lock sys_lock;

void
syscall_init (void)
{
  lock_init (&sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  for(int i=0; i<21; i++)
    pfn[i]=NULL;

  pfn[SYS_WRITE]=IWrite;
  pfn[SYS_EXIT]=IExit;
  pfn[SYS_CREATE]=ICreate;
  pfn[SYS_OPEN]=IOpen;
  pfn[SYS_CLOSE]=IClose;
  pfn[SYS_READ]=IRead;
  pfn[SYS_FILESIZE]=IFileSize;
  pfn[SYS_EXEC]=IExec;
  pfn[SYS_WAIT]=IWait;
  pfn[SYS_SEEK]=ISeek;
  pfn[SYS_REMOVE]=IRemove;
  pfn[SYS_TELL]=ITell;
  pfn[SYS_HALT]=IHalt;
}

void IWrite(struct intr_frame *f) 
{
  int *sys_buffer = (int *)f->esp + 1;
  int *sys_size = (int *)f->esp + 2;
  int *sys_size1 = (int *)f->esp + 3;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_addr ((const char *)sys_size);
  is_valid_addr ((const char *)sys_size1);
  is_valid_buffer ((void *)(*sys_size), (unsigned)(*sys_size1));
  f->eax = write (*sys_buffer, (const void *)(*sys_size), (unsigned)(*sys_size1));
}
void IExit(struct intr_frame *f) 
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  struct child_process *child = thread_current ()->child;
  if (child != NULL)
    child->ret = *sys_buffer;
  printf ("%s: exit(%d)\n", thread_current ()->name, *sys_buffer);
  thread_exit ();
}
void ICreate(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  int *sys_size = (int *)f->esp + 2;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_addr ((const char *)sys_size);
  is_valid_buffer ((void *)(*sys_buffer), (unsigned)(*sys_size));
  f->eax = create ((const char*)(*sys_buffer),(unsigned)(*sys_size));

}
void IOpen(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_buffer ((void *)(*sys_buffer), 0);
  f->eax = open ((const char *)(*sys_buffer));
}
void IClose(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  close(*sys_buffer);
}

void IRead(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  int *sys_size = (int *)f->esp + 2;
  int *sys_size1 = (int *)f->esp + 3;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_addr ((const char *)sys_size1);
  is_valid_buffer ((void *)(*sys_size), (unsigned)(*sys_size1));
  f->eax = read (*sys_buffer, (void *)(*sys_size), (unsigned)(*sys_size1));
}

void IFileSize(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  f->eax = filesize (*sys_buffer);
}
void IExec(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_buffer ((void *)(*sys_buffer), 0);

  lock_acquire (&sys_lock);
  tid_t tid = process_execute ((const char*)(*sys_buffer));
  lock_release (&sys_lock);
  f->eax = (pid_t)tid;
}

void IWait(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  f->eax = process_wait ((pid_t)(*sys_buffer));
}

void ISeek(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  int *sys_size = (int *)f->esp + 2;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_addr ((const char *)sys_size);
  seek(*sys_buffer, (unsigned)(*sys_size));
}

void IRemove(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  is_valid_buffer ((void *)(*sys_buffer), 0);
  f->eax = remove ((const char*)(*sys_buffer));
}

void ITell(struct intr_frame *f)
{
  int *sys_buffer = (int *)f->esp + 1;
  is_valid_addr ((const char *)sys_buffer);
  f->eax = tell(*sys_buffer);
}
void IHalt(struct intr_frame *f)
{
  shutdown_power_off ();
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int *sys_call = (int *)f->esp;
  is_valid_addr (sys_call);
  if ((int)(*sys_call) < 1 || (int)(*sys_call) > 19)
    exit (-1);
  pfn[*sys_call](f);
}


struct file_node *
get_node (int fd)
{
  struct file_node *node = NULL;
  struct thread *cur = thread_current ();
  struct list_elem *e;
  /* Search node in file_list */
  if (list_empty(&cur->file_list))
    return NULL;
  for(e = list_begin (&cur->file_list); e != list_end (&cur->file_list); e = list_next (e))
    {
      node = list_entry(e, struct file_node, elem);
      if(node->fd == fd)
        return node;
    }
  return NULL;
}

void
is_valid_addr (const void *addr)
{
  if (addr == NULL || !is_user_vaddr (addr) || pagedir_get_page (thread_current ()->pagedir, addr) == NULL)
    {
      if (lock_held_by_current_thread (&sys_lock))
        lock_release (&sys_lock);
      exit (-1);
    }
}

void
is_valid_buffer (void *buffer, unsigned size)
{
  char *temp = (char *)buffer;
  for (unsigned i = 0; i <= size; i++)
    {
      is_valid_addr ((const char *)temp);
      temp++;
    }
}


bool
create (const char *file, unsigned initial_size)
{
  bool temp;
  lock_acquire (&sys_lock);
  temp =  filesys_create (file, initial_size);
  lock_release (&sys_lock);
  return temp;
}

bool
remove (const char *file)
{
  bool temp;
  lock_acquire (&sys_lock);
  temp =  filesys_remove (file);
  lock_release (&sys_lock);
  return temp;
}

int
open (const char *file)
{
  struct file_node* node = palloc_get_page(0);
  if (!node)
    return -1;

  struct file *file_open;
  lock_acquire (&sys_lock);
  file_open = filesys_open(file);
  if (!file_open) {
    palloc_free_page (node);
    lock_release (&sys_lock);
    return -1;
  }
  node->file = file_open;

  struct list* file_list = &thread_current()->file_list;
  if (list_empty (file_list))
    node->fd = 3;
  else
    node->fd = (list_entry (list_back (file_list), struct file_node, elem)->fd) + 1;
  list_push_back(file_list, &node->elem);
  lock_release (&sys_lock);
  return node->fd;
}

int
filesize (int fd)
{
  struct file_node *node = NULL;
  int temp;
  lock_acquire (&sys_lock);
  node = get_node (fd);
  if (node == NULL) {
    lock_release (&sys_lock);
    return -1;
  }
  temp = file_length(node->file);
  lock_release (&sys_lock);
  return temp;
}

int
read (int fd, void *buffer, unsigned size)
{
  lock_acquire (&sys_lock);
  if(fd == STDIN_FILENO)
    {
      for(unsigned i = 0; i < size; i++)
        *(uint8_t *)(buffer + i) = input_getc ();
      lock_release (&sys_lock);
      return (int)size;
    }

  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  int temp = file_read (node->file, buffer, size);
  lock_release (&sys_lock);
  return temp;
}

int
write (int fd, const void *buffer, unsigned size)
{
  lock_acquire (&sys_lock);
  if(fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      lock_release (&sys_lock);
      return size;
    }
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  int temp = file_write (node->file, buffer, size);
  lock_release (&sys_lock);
  return temp;
}

void
seek (int fd, unsigned position)
{
  lock_acquire (&sys_lock);
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return;
    }
  file_seek(node->file, position);
  lock_release (&sys_lock);
}

unsigned
tell (int fd)
{
  lock_acquire (&sys_lock);
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  unsigned temp = file_tell (node->file);
  lock_release (&sys_lock);
  return temp;
}

void
close (int fd)
{
  lock_acquire (&sys_lock);
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return;
    }
  file_close(node->file);
  list_remove(&node->elem);
  palloc_free_page(node);
  lock_release (&sys_lock);
}
