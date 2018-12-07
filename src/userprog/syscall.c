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

static void syscall_handler (struct intr_frame *);

void is_valid_addr (const void *addr);
void is_valid_buffer (void *buffer, unsigned size);

struct file_node *get_node (int fd);
void halt (void);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

struct lock sys_lock;

void
syscall_init (void)
{
  lock_init (&sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int *sys_call = (int *)f->esp;
  is_valid_addr (sys_call);
  if ((int)(*sys_call) < 1 || (int)(*sys_call) > 19)
    exit (-1);
  int *sys_buffer = (int *)f->esp + 1;
  int *sys_size = (int *)f->esp + 2;
  int *sys_size1 = (int *)f->esp + 3;

  switch(*sys_call){
    case SYS_HALT:
    {
      halt ();
      break;
    }
    case SYS_EXIT:
    {
      is_valid_addr ((const char *)sys_buffer);
      exit(*sys_buffer);
      break;
    }
    case SYS_EXEC:
    {
      /* Check both addr and content. */
      is_valid_addr ((const char *)sys_buffer);
      is_valid_buffer ((void *)(*sys_buffer), 0);
      f->eax = exec ((const char*)(*sys_buffer));
      break;
    }
    case SYS_WAIT:
    {
      is_valid_addr ((const char *)sys_buffer);
      f->eax = wait ((pid_t)(*sys_buffer));
      break;
    }
    case SYS_CREATE:
    {
      is_valid_addr ((const char *)sys_buffer);
      is_valid_addr ((const char *)sys_size);
      is_valid_buffer ((void *)(*sys_buffer), (unsigned)(*sys_size));
      f->eax = create ((const char*)(*sys_buffer),(unsigned)(*sys_size));
      break;
    }
    case SYS_REMOVE:
    {
      is_valid_addr ((const char *)sys_buffer);
      is_valid_buffer ((void *)(*sys_buffer), 0);
      f->eax = remove ((const char*)(*sys_buffer));
      break;
    }
    case SYS_OPEN:
    {
      is_valid_addr ((const char *)sys_buffer);
      is_valid_buffer ((void *)(*sys_buffer), 0);
      f->eax = open ((const char *)(*sys_buffer));
      break;
    }
    case SYS_FILESIZE:
    {
      is_valid_addr ((const char *)sys_buffer);
      f->eax = filesize (*sys_buffer);
      break;
    }
    case SYS_READ:
    {
      is_valid_addr ((const char *)sys_buffer);
      is_valid_addr ((const char *)sys_size1);
      is_valid_buffer ((void *)(*sys_size), (unsigned)(*sys_size1));
      f->eax = read (*sys_buffer, (void *)(*sys_size), (unsigned)(*sys_size1));
      break;
    }

    case SYS_WRITE:
    {
      is_valid_addr ((const char *)sys_buffer);
      is_valid_addr ((const char *)sys_size);
      is_valid_addr ((const char *)sys_size1);
      is_valid_buffer ((void *)(*sys_size), (unsigned)(*sys_size1));
      f->eax = write (*sys_buffer, (const void *)(*sys_size), (unsigned)(*sys_size1));

      break;
    }

    case SYS_SEEK:
    {
      is_valid_addr ((const char *)sys_buffer);
      is_valid_addr ((const char *)sys_size);
      seek(*sys_buffer, (unsigned)(*sys_size));
      break;
    }
    case SYS_TELL:
    {
      is_valid_addr ((const char *)sys_buffer);
      f->eax = tell(*sys_buffer);
      break;
    }
    case SYS_CLOSE:
    {
      is_valid_addr ((const char *)sys_buffer);
      close(*sys_buffer);
      break;
    }
  }
}


struct file_node *
get_node (int fd)
{
  struct file_node *node = NULL;
  struct thread *cur = thread_current ();
  struct list_elem *e;
  /* Search node in file_list */
  if (list_empty(&cur->fn_list))
    return NULL;
  for(e = list_begin (&cur->fn_list); e != list_end (&cur->fn_list); e = list_next (e))
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
/*
char *
user_to_kernel_vaddr (const char *vaddr)
{
  is_valid_addr (vaddr);
  char *ptr = pagedir_get_page(thread_current()->pagedir, (const void *)vaddr);
  if (!ptr)
    exit(-1);
  return ptr;
}*/

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

void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct child_process *child = thread_current ()->child;
  if (child != NULL)
    child->exit = status;
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}

pid_t
exec (const char *cmd_line)
{
  lock_acquire (&sys_lock);
  pid_t pid = (pid_t)process_execute (cmd_line);
  lock_release (&sys_lock);
  return pid;
}

int
wait (pid_t pid)
{
  return process_wait (pid);
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

  struct list* fn_list = &thread_current()->fn_list;
  if (list_empty (fn_list))
    node->fd = 3;
  else
    node->fd = (list_entry (list_back (fn_list), struct file_node, elem)->fd) + 1;
  list_push_back(fn_list, &node->elem);
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
