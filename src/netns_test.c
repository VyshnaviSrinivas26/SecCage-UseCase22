#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
int main(){printf("Network namespace test started.\n"); int sock=socket(AF_INET,SOCK_STREAM,0); if(sock==-1){perror("Socket creation");return 1;} printf("Socket syscall allowed.\n"); return 0;}
