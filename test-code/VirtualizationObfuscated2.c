/* Generated by CIL v. 1.7.3 */
/* print_CIL_Input is false */

union _1_main_$node ;
struct _IO_FILE ;
enum _1_main_$op ;
struct timeval ;
extern int gettimeofday(struct timeval *tv , void *tz ) ;
extern int pthread_cond_broadcast(int *cond ) ;
char **_global_argv  =    (char **)0;
extern int posix_memalign(void **memptr , unsigned int alignment , unsigned int size ) ;
extern int getpagesize() ;
extern int pthread_join(void *thread , void **value_ptr ) ;
extern int open(char const   *filename , int oflag  , ...) ;
extern unsigned int strlen(char const   *s ) ;
extern int pthread_barrier_destroy(int *barrier ) ;
union _1_main_$node {
   char _char ;
   unsigned int _unsigned_int ;
   unsigned char _unsigned_char ;
   long _long ;
   unsigned long _unsigned_long ;
   void *_void_star ;
   unsigned short _unsigned_short ;
   unsigned long long _unsigned_long_long ;
   signed char _signed_char ;
   long long _long_long ;
   int _int ;
   short _short ;
};
extern int pthread_mutex_init(int *mutex , int *attr ) ;
extern int strncmp(char const   *s1 , char const   *s2 , unsigned int maxlen ) ;
extern int printf(char const   *format  , ...) ;
int _global_argc  =    0;
extern int pthread_cond_signal(int *cond ) ;
extern int raise(int sig ) ;
extern int pthread_barrier_init(int *barrier , int *attr , unsigned int count ) ;
extern int scanf(char const   *format  , ...) ;
char **_global_envp  =    (char **)0;
extern int unlink(char const   *filename ) ;
extern double difftime(long tv1 , long tv0 ) ;
extern int pthread_barrier_wait(int *barrier ) ;
extern void *memcpy(void *s1 , void const   *s2 , unsigned int size ) ;
extern int pthread_mutex_lock(int *mutex ) ;
extern void *dlsym(void *handle , char *symbol ) ;
extern int gethostname(char *name , unsigned int namelen ) ;
extern void abort() ;
extern unsigned long strtoul(char const   *str , char const   *endptr , int base ) ;
extern int fprintf(struct _IO_FILE *stream , char const   *format  , ...) ;
extern void free(void *ptr ) ;
void main(int _formal_argc , char **_formal_argv , char **_formal_envp ) ;
extern void exit(int status ) ;
extern void signal(int sig , void *func ) ;
typedef struct _IO_FILE FILE;
extern int close(int filedes ) ;
extern int mprotect(void *addr , unsigned int len , int prot ) ;
extern double strtod(char const   *str , char const   *endptr ) ;
extern double log(double x ) ;
extern double ceil(double x ) ;
extern int fcntl(int filedes , int cmd  , ...) ;
extern int fclose(void *stream ) ;
enum _1_main_$op {
    _1_main__returnVoid$ = 154,
    _1_main__constant_int$result_STA_0$value_LIT_0 = 126,
    _1_main__goto$label_LAB_0 = 170,
    _1_main__load_int$left_STA_0$result_STA_0 = 160,
    _1_main__local$result_STA_0$value_LIT_0 = 198,
    _1_main__store_int$left_STA_0$right_STA_1 = 62,
    _1_main__BOr_int_int2int$right_STA_0$result_STA_0$left_STA_1 = 63
} ;
unsigned char _1_main_$array[1][58]  = { {        _1_main__constant_int$result_STA_0$value_LIT_0,        (unsigned char)160,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_main__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_main__store_int$left_STA_0$right_STA_1,        _1_main__constant_int$result_STA_0$value_LIT_0, 
            (unsigned char)95,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_main__local$result_STA_0$value_LIT_0,        (unsigned char)28,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_main__store_int$left_STA_0$right_STA_1,        _1_main__constant_int$result_STA_0$value_LIT_0,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_main__local$result_STA_0$value_LIT_0, 
            (unsigned char)32,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_main__store_int$left_STA_0$right_STA_1,        _1_main__local$result_STA_0$value_LIT_0,        (unsigned char)24,        (unsigned char)0, 
            (unsigned char)0,        (unsigned char)0,        _1_main__load_int$left_STA_0$result_STA_0,        _1_main__local$result_STA_0$value_LIT_0, 
            (unsigned char)28,        (unsigned char)0,        (unsigned char)0,        (unsigned char)0, 
            _1_main__load_int$left_STA_0$result_STA_0,        _1_main__BOr_int_int2int$right_STA_0$result_STA_0$left_STA_1,        _1_main__local$result_STA_0$value_LIT_0,        (unsigned char)32, 
            (unsigned char)0,        (unsigned char)0,        (unsigned char)0,        _1_main__store_int$left_STA_0$right_STA_1, 
            _1_main__goto$label_LAB_0,        (unsigned char)4,        (unsigned char)0,        (unsigned char)0, 
            (unsigned char)0,        _1_main__returnVoid$}};
extern int pthread_cond_wait(int *cond , int *mutex ) ;
extern void perror(char const   *str ) ;
extern int pthread_cond_init(int *cond , int *attr ) ;
extern int write(int filedes , void *buf , unsigned int nbyte ) ;
extern int ptrace(int request , void *pid , void *addr , int data ) ;
extern float strtof(char const   *str , char const   *endptr ) ;
extern unsigned int strnlen(char const   *s , unsigned int maxlen ) ;
struct timeval {
   long tv_sec ;
   long tv_usec ;
};
extern void qsort(void *base , unsigned int nel , unsigned int width , int (*compar)(void *a ,
                                                                                     void *b ) ) ;
extern long clock(void) ;
extern long time(long *tloc ) ;
extern int read(int filedes , void *buf , unsigned int nbyte ) ;
extern int rand() ;
extern int strcmp(char const   *a , char const   *b ) ;
extern void *fopen(char const   *filename , char const   *mode ) ;
extern double sqrt(double x ) ;
extern long strtol(char const   *str , char const   *endptr , int base ) ;
extern int snprintf(char *str , unsigned int size , char const   *format  , ...) ;
extern void *malloc(unsigned int size ) ;
extern int nanosleep(int *rqtp , int *rmtp ) ;
char const   *_1_main_$strings  =    "";
extern int pthread_mutex_unlock(int *mutex ) ;
extern int pthread_create(void *thread , void *attr , void *start_routine , void *arg ) ;
extern int atoi(char const   *s ) ;
extern int fseek(struct _IO_FILE *stream , long offs , int whence ) ;
extern int fscanf(struct _IO_FILE *stream , char const   *format  , ...) ;
void megaInit(void) ;
void megaInit(void) 
{ 


  {

}
}
void main(int _formal_argc , char **_formal_argv , char **_formal_envp ) 
{ 
  int _BARRIER_0 ;
  char _1_main_$locals[36] ;
  union _1_main_$node _1_main_$stack[1][32] ;
  union _1_main_$node *_1_main_$sp[1] ;
  unsigned char *_1_main_$pc[1] ;

  {
  megaInit();
  _global_argc = _formal_argc;
  _global_argv = _formal_argv;
  _global_envp = _formal_envp;
  _BARRIER_0 = 1;
  _1_main_$sp[0] = _1_main_$stack[0];
  _1_main_$pc[0] = _1_main_$array[0];
  while (1) {
    switch (*(_1_main_$pc[0])) {
    case _1_main__goto$label_LAB_0: 
    (_1_main_$pc[0]) ++;
    _1_main_$pc[0] += *((int *)_1_main_$pc[0]);
    break;
    case _1_main__returnVoid$: 
    (_1_main_$pc[0]) ++;
    return;
    break;
    case _1_main__BOr_int_int2int$right_STA_0$result_STA_0$left_STA_1: 
    (_1_main_$pc[0]) ++;
    (_1_main_$sp[0] + -1)->_int = (_1_main_$sp[0] + -1)->_int | (_1_main_$sp[0] + 0)->_int;
    (_1_main_$sp[0]) --;
    break;
    case _1_main__load_int$left_STA_0$result_STA_0: 
    (_1_main_$pc[0]) ++;
    (_1_main_$sp[0] + 0)->_int = *((int *)(_1_main_$sp[0] + 0)->_void_star);
    break;
    case _1_main__constant_int$result_STA_0$value_LIT_0: 
    (_1_main_$pc[0]) ++;
    (_1_main_$sp[0] + 1)->_int = *((int *)_1_main_$pc[0]);
    (_1_main_$sp[0]) ++;
    _1_main_$pc[0] += 4;
    break;
    case _1_main__store_int$left_STA_0$right_STA_1: 
    (_1_main_$pc[0]) ++;
    *((int *)(_1_main_$sp[0] + 0)->_void_star) = (_1_main_$sp[0] + -1)->_int;
    _1_main_$sp[0] += -2;
    break;
    case _1_main__local$result_STA_0$value_LIT_0: 
    (_1_main_$pc[0]) ++;
    (_1_main_$sp[0] + 1)->_void_star = (void *)(_1_main_$locals + *((int *)_1_main_$pc[0]));
    (_1_main_$sp[0]) ++;
    _1_main_$pc[0] += 4;
    break;
    }
  }
}
}
