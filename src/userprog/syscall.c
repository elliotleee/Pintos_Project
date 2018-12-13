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
  int *pointer = (int *)f->esp;
  
  is_valid_addr ((const char *)pointer + 1);
  is_valid_addr ((const char *)(pointer + 2));
  is_valid_buffer ((void *)(*(pointer + 2)), (unsigned)(*(pointer + 3)));
  f->eax = write (*(pointer + 1), (const void *)(*(pointer + 2)), (unsigned)(*(pointer + 3)));
}
int write (int fd, const void *buffer, unsigned size)
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
void IExit(struct intr_frame *f) {
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  exit(*(pointer + 1));
}
void exit (int status){
  if (thread_current ()->child)
    thread_current ()->child->ret = status;
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}
void ICreate(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  is_valid_addr ((const char *)(pointer + 2));
  is_valid_buffer ((void *)(*(pointer + 1)), (unsigned)(*(pointer + 2)));
  f->eax = create ((const char*)(*(pointer + 1)),(unsigned)(*(pointer + 2)));
}

bool create (const char *file, unsigned initial_size)
{
  lock_acquire (&sys_lock);
  bool temp = filesys_create (file, initial_size);
  lock_release (&sys_lock);
  return temp;
}

void IOpen(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  is_valid_buffer ((void *)(*(pointer + 1)), 0);
  f->eax = open ((const char *)(*(pointer + 1)));
}
int open (const char *file)
{
  struct file_node* node = palloc_get_page(0);
  if (node == NULL)
    return -1;
  else{
    lock_acquire (&sys_lock);
    struct file* file_open = filesys_open(file);
    if (file_open == NULL) {
      palloc_free_page (node);
      lock_release (&sys_lock);
      return -1;
    }
    node->file = file_open;

    struct list* file_list = &thread_current()->file_list;
    bool emptymark = list_empty (file_list);
    if (emptymark)
      node->fd = 3;
    else
      node->fd = (list_entry (list_back (file_list), struct file_node, elem)->fd) + 1;
    list_push_back(file_list, &node->elem);
    lock_release (&sys_lock);
    return node->fd;
  }
}
void IClose(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  close(*(pointer + 1));
}
void close (int fd)
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

void IRead(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  is_valid_addr ((const char *)(pointer + 3));
  is_valid_buffer ((void *)(*(pointer + 2)), (unsigned)(*(pointer + 3)));
  f->eax = read (*(pointer + 1), (void *)(*(pointer + 2)), (unsigned)(*(pointer + 3)));
}
int read (int fd, void *buffer, unsigned size)
{
  int sizeint = (int)size;
  lock_acquire (&sys_lock);
  if(fd == STDIN_FILENO)
    {
      for(unsigned i = 0; i < size; i++)
        *(uint8_t *)(buffer + i) = input_getc ();
      lock_release (&sys_lock);
      return sizeint;
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

void IFileSize(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  f->eax = filesize (*(pointer + 1));
}
void IExec(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  is_valid_buffer ((void *)(*(pointer + 1)), 0);
  f->eax = exec ((const char*)(*(pointer + 1)));
}
pid_t exec (const char *cmd_line)
{
  lock_acquire (&sys_lock);
  pid_t pid = (pid_t)process_execute (cmd_line);
  lock_release (&sys_lock);
  return pid;
}


void IWait(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  f->eax = process_wait ((pid_t)(*(pointer + 1)));
}

void ISeek(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  is_valid_addr ((const char *)(pointer + 2));
  seek(*(pointer + 1), (unsigned)(*(pointer + 2)));
}
void seek (int fd, unsigned position)
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

void IRemove(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  is_valid_buffer ((void *)(*(pointer + 1)), 0);
  f->eax = remove ((const char*)(*(pointer + 1)));
}
bool remove (const char *file)
{
  lock_acquire (&sys_lock);
  bool temp =  filesys_remove (file);
  lock_release (&sys_lock);
  return temp;
}


void ITell(struct intr_frame *f)
{
  int *pointer = (int *)f->esp;
  is_valid_addr ((const char *)(pointer + 1));
  f->eax = tell(*(pointer + 1));
}
unsigned tell (int fd)
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

void IHalt(struct intr_frame *f)
{
  shutdown_power_off ();
}


static void syscall_handler (struct intr_frame *f UNUSED)
{
  int *sys_call = (int *)f->esp;
  is_valid_addr (sys_call);

  if ((int)(*sys_call) <= 0)
    exit (-1);
  else if( (int)(*sys_call) >= 20){
    exit (-1);
  }

  pfn[*sys_call](f);
}


struct file_node * get_node (int fd)
{
  struct file_node *node = NULL;
  struct thread *t = thread_current ();
  
  /* Search node in file_list */
  if (list_empty(&t->file_list))
    return NULL;

  for(struct list_elem *e = list_begin (&t->file_list); e != list_end (&t->file_list); e = list_next (e))
    {
      node = list_entry(e, struct file_node, elem);
      if(node->fd == fd)
        return node;
    }
  return NULL;
}

void is_valid_addr (const void *addr)
{
  if (!addr || !is_user_vaddr (addr) || !(pagedir_get_page (thread_current ()->pagedir, addr) ))
    {
      if (lock_held_by_current_thread (&sys_lock))
        lock_release (&sys_lock);
      exit (-1);
    }
}

void is_valid_buffer (void *buffer, unsigned size)
{
  char *temp = (char *)buffer;
  for (unsigned i = 0; i <= size; i++)
    {
      is_valid_addr ((const char *)temp);
      temp++;
    }
}







int filesize (int fd)
{
  struct file_node *node = NULL;
  lock_acquire (&sys_lock);
  node = get_node (fd);
  if (!node) {
    lock_release (&sys_lock);
    return -1;
  }
  int temp = file_length(node->file);
  lock_release (&sys_lock);
  return temp;
}










