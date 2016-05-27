#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>

static const char *opened[100];
static int idx = 0;
static int(*orig_open)(const char *pathname, int flags);
static int(*orig_socket)(int domain, int type, int protocol);
static int (*orig_bind)(int socket, const struct sockaddr *address,
            socklen_t address_len);
static ssize_t (*orig_recvfrom)(int socket, void *buffer, size_t length, int flags,
            struct sockaddr *address, socklen_t *address_len);

//int open(const char *pathname, int flags, ...)
//{
//    idx++;
//    opened[idx-1] = pathname;
//    printf("Opened so far:%i\n", idx);
//    for (int i=0;i<idx;i++)
//    {
//        printf("> %s\n", opened[i]);
//    }
//    if (!orig_open) orig_open=dlsym(RTLD_NEXT, "open");
//    return orig_open(pathname, flags);
//}

// gives us the file descriptor
int socket(int domain, int type, int protocol)
{
    if(!orig_socket) orig_socket=dlsym(RTLD_NEXT, "socket");
    printf("opened socket! \n");
    return orig_socket(domain, type, protocol);
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len)
{
    if(!orig_bind) orig_bind=dlsym(RTLD_NEXT, "bind");
    printf(">> called bind <<\n");
    return orig_bind(socket, address, address_len);
}

ssize_t recvfrom(int socket, void *buffer, size_t length, int flags,
             struct sockaddr *address, socklen_t *address_len)
{
    if(orig_recvfrom == 0) orig_recvfrom=dlsym(RTLD_NEXT, "recvfrom");
    printf(">> called recvfrom <<\n");
    return orig_recvfrom(socket, buffer, length, flags, address, address_len);
}

// override READ. Check if the fd is a socket and redidrect it
// bind
// listen
// accept
// close
// fstat
