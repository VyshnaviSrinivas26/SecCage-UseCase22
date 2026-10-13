#include <stdio.h>
#include <sys/resource.h>
#include "limits.h"
int apply_cpu_limit(int seconds){struct rlimit l={seconds,seconds+1}; if(setrlimit(RLIMIT_CPU,&l)==-1){perror("[SecCage] CPU limit failed");return -1;} printf("[SecCage] CPU soft limit: %d seconds\n",seconds); printf("[SecCage] CPU hard limit: %d seconds\n",seconds+1); return 0;}
int apply_memory_limit(int megabytes){struct rlimit l; rlim_t b=(rlim_t)megabytes*1024*1024; l.rlim_cur=b;l.rlim_max=b; if(setrlimit(RLIMIT_AS,&l)==-1){perror("[SecCage] Memory limit failed");return -1;} printf("[SecCage] Memory limit: %d MB\n",megabytes);return 0;}
int apply_file_limit(int files){struct rlimit l={files,files}; if(setrlimit(RLIMIT_NOFILE,&l)==-1){perror("[SecCage] File descriptor limit failed");return -1;} printf("[SecCage] File descriptor limit: %d\n",files);return 0;}
