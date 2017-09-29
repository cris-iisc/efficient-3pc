#include "socket.h"


int socket_connect(const char* addr, int port){
    struct sockaddr_in dest;
    int socket_fds;
    int optval=1;

    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(addr);
    dest.sin_port = htons(port);

    if((socket_fds = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <0){
        printf("Socket() fail. Error no=%d \n", errno);
        return -1;
    }
    setsockopt(socket_fds, IPPROTO_TCP, TCP_NODELAY, (char *) &optval, sizeof(int));
    if(connect(socket_fds, (struct sockaddr *)(&dest), sizeof(sockaddr)) <0){
        printf("connect() fail. Error no=%d \n", errno);
        return -2;
    }

    return socket_fds;
}

//Use for the server.
int socket_bind_listen(const char* addr, int port){
    sockaddr_in socket_addr;
    int socket_fds;
    int optval=1;

    memset(&socket_addr, 0, sizeof(struct sockaddr));
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_addr.s_addr = inet_addr(addr);
    socket_addr.sin_port = htons(port);

    if((socket_fds = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <0){
        printf("Socket() fail. Error no=%d \n", errno);
        return -1;
    }
    setsockopt(socket_fds, IPPROTO_TCP, TCP_NODELAY, (char *) &optval, sizeof(int));
    if(bind(socket_fds, (sockaddr *)(&socket_addr), sizeof(socket_addr))<0){
        printf("bind() fail. Error no=%d\n", errno);
    }
    listen(socket_fds, SOMAXCONN);
    return socket_fds;
}
