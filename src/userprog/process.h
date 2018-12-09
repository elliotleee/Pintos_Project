#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct file_node {
  int fd;
  struct list_elem elem;
  struct file *file;
};

struct child_process {

  char *file_name;    /* Transfer file_name to start process */

  tid_t tid;                /* Id of child process */

  tid_t father_tid; //~~~~

  struct list_elem elem;    /* For list */

  bool waiting;             /* If child process is being waited. */
  bool finish;              /* If child process finished. */
  bool parent_finish;       /* If parent has terminated. */

  int exit;                 /* Exit code. */

  struct semaphore child_wait;             /* the semaphore used for wait() : parent blocks until child exits */

};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct child_process *get_child(struct list *child_list, tid_t child_tid);
void close_all_file();
void release_all_child();
char *make_copy(const char *file_name);
struct child_process* init_child(char* fn_copy);

#endif /* userprog/process.h */
