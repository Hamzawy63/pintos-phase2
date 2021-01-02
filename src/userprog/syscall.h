#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* get int from the stack */
int get_int(int** esp);

/* get character pointer */
char* get_char_ptr(char*** esp);

/* get void pointer */
void* get_void_ptr(void*** esp);

/* check if the pointer is valid */
void validate_void_ptr(const void* pt);

#endif /* userprog/syscall.h */
