#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int(*orig_open)(const char *pathname, int flags);
static int(*orig_socket)(int domain, int type, int protocol);
static int (*orig_bind)(int socket, const struct sockaddr *address,
            socklen_t address_len);
static ssize_t (*orig_recvfrom)(int socket, void *buffer, size_t length, int flags,
            struct sockaddr *address, socklen_t *address_len);
static ssize_t (*orig_recv)(int sockfd, void *buf, size_t len, int flags);
static int (*orig_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
static int (*orig_listen)(int sockfd, int backlog);
static ssize_t (*orig_read)(int fd, void *buf, size_t count);
static ssize_t (*orig_write)(int fd, const void *buf, size_t count);
static int (*orig_close)(int fd);
static int (*orig_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*orig_connect)(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);

static int publish(int bw_sock, const char *uri, const void *data, size_t count);
static int subscribe(int bw_sock, const char *uri, void *data, size_t count);

// array of socket FDs that we emulate over bosswave
static int socket_fds[1024];
// index is FD. Content is the URI for that FD
static const char* socket_uris[1024];

static bool initialized = false;
static const char* entity_file = "currently path to entity file";
static const char* namespace = "namespace prefix, no /";
static char entity[256];
static int bw_sock;
static struct sockaddr_in bw_server;

// performs the setups we need
static void init(void)
{
    // initialize array of emulated sockets
    memset(socket_fds, -1, sizeof(socket_fds));

    // load in original functions
    orig_open=dlsym(RTLD_NEXT, "open");
    orig_socket=dlsym(RTLD_NEXT, "socket");
    orig_bind=dlsym(RTLD_NEXT, "bind");
    orig_recvfrom=dlsym(RTLD_NEXT, "recvfrom");
    orig_recv=dlsym(RTLD_NEXT, "recv");
    orig_listen=dlsym(RTLD_NEXT, "listen");
    orig_read=dlsym(RTLD_NEXT, "read");
    orig_poll=dlsym(RTLD_NEXT, "poll");
    orig_write=dlsym(RTLD_NEXT, "write");
    orig_close=dlsym(RTLD_NEXT, "close");
    orig_accept=dlsym(RTLD_NEXT, "accept");
    orig_connect=dlsym(RTLD_NEXT, "connect");

    bw_server.sin_family = AF_INET;
    bw_server.sin_port = htons(28589);
    bw_server.sin_addr.s_addr = inet_addr("127.0.0.1");
    bw_sock = orig_socket(AF_INET, SOCK_STREAM, 0);
    if (bw_sock < 0)
    {
        printf("Could not create BW socket!\n");
    }
    printf("bw fd %i\n", bw_sock);

    if (orig_connect(bw_sock, (struct sockaddr *)&bw_server, sizeof(bw_server)) < 0) {
        printf("Could not connect to local BW\n");
    }

    int numread = 0;
    char buf[512];
    while (numread == 0)
    {
        numread = orig_read(bw_sock, buf, 1024);
    }
    printf("from bw sock>>>%.*s",numread,buf);

    // set up our entity
    //entity = getenv("BW2_DEFAULT_ENITTY");
    printf("entity %s\n", entity_file);
    // retrieve entity
    struct stat entity_stat;
    if (stat(entity_file, &entity_stat) < 0)
    {
        printf("Error getting entity file %s\n", entity_file);
    }
    int entity_size = (int)entity_stat.st_size;

    printf("entity is %i bytes\n", entity_size);
    // read entity
    int entity_fd = orig_open(entity_file, O_RDONLY);
    if (entity_fd < 0)
    {
        printf("Could not open entity file %s\n", entity_file);
    }
    printf("opened entity fd %d\n", entity_fd);

    int num_read = orig_read(entity_fd, &entity, entity_size);
    if (num_read < entity_size)
    {
        printf("Could not read entity!\n");
    }

    entity_size--;

    int written = 0;
    written += sprintf(buf, "sete %010d %010d\npo :50 %d\n", 0, 1, entity_size);
    memcpy(buf+written, entity+1, entity_size);
    written += entity_size;
    written += sprintf(buf+written, "\nend\n");
    if (orig_write(bw_sock, buf, written) != written)
    {
        printf("Unsuccessfully wrote entity to router\n");
    }
    //printf("%.*s",written,buf);

    numread = 0;
    while (numread == 0)
    {
        numread = orig_read(bw_sock, buf, 1024);
    }
    printf("from bw sock>>>%.*s",numread,buf);

    initialized = true;
}

// returns true if we have the FD in our internal list
static bool have_fd(int fd)
{
    for (int i=0; i<1024; i++)
    {
        if ((socket_fds[i]) == fd)
        {
            return true;
        }
    }
    return false;
}

static void add_fd(int fd)
{
    for (int i=0; i<1024; i++)
    {
        if (socket_fds[i] < 0)
        {
            socket_fds[i] = fd;
            return;
        }
    }
}

// gives us the file descriptor
int socket(int domain, int type, int protocol)
{
    if(!initialized) init();
    printf(">> called socket <<\n");
    int fd = orig_socket(domain, type, protocol);
    printf("Socket got FD %d\n", fd);
    add_fd(fd);
    return fd;
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len)
{
    if(!initialized) init();
    printf(">> called bind: socket %d<<\n", socket);
    printf("have fd? %d\n", have_fd(socket));
    struct sockaddr_in *ip_src = (struct sockaddr_in*)address;
    char *uri = malloc(128);
    sprintf(uri, "%s/%s/%d", namespace, inet_ntoa(ip_src->sin_addr), ip_src->sin_port);
    printf("uri for sub %s\n", uri);
    socket_uris[socket] = uri;

    return orig_bind(socket, address, address_len);
}

ssize_t recvfrom(int socket, void *buffer, size_t length, int flags,
             struct sockaddr *address, socklen_t *address_len)
{
    if(!initialized) init();
    printf(">> called recvfrom <<\n");
    return orig_recvfrom(socket, buffer, length, flags, address, address_len);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    if(!initialized) init();
    printf(">> called recv: socket %d <<\n", sockfd);
    if (have_fd(sockfd))
    {
        subscribe(bw_sock, socket_uris[sockfd], buf, len);
    }
    return orig_recv(sockfd, buf, len, flags);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if(!initialized) init();
    printf(">> called poll <<\n");
    return orig_poll(fds, nfds, timeout);
}

int listen(int sockfd, int backlog)
{
    if(!initialized) init();
    printf(">> called listen: socket %d <<\n", sockfd);
    return orig_listen(sockfd, backlog);
}

ssize_t read(int fd, void *buf, size_t count)
{
    if(!initialized) init();
    printf(">> called read <<\n");
    if (have_fd(fd))
    {
        //subscribe(bw_sock, socket_uris[fd], buf, count);
    }
    return orig_read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    if(!initialized) init();
    printf(">> called write <<\n");
    if (have_fd(fd))
    {
        publish(bw_sock, socket_uris[fd], buf, count);
    }
    return orig_write(fd, buf, count);
}

int close(int fd)
{
    if(!initialized) init();
    printf(">> called close <<\n");
    return orig_close(fd);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if(!initialized) init();
    printf(">> called accept: socket %d<<\n", sockfd);
    int incoming_fd = orig_accept(sockfd, addr, addrlen);
    add_fd(incoming_fd);
    struct sockaddr_in *ip_src = (struct sockaddr_in*)addr;
    char uri[128];
    sprintf(uri, "%s/%s/%d", namespace, inet_ntoa(ip_src->sin_addr), ip_src->sin_port);
    printf("uri for sub %s\n", uri);
    return incoming_fd;
}

int connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if(!initialized) init();
    printf(">> called connect <<\n");
    struct sockaddr_in *ip_dst = (struct sockaddr_in*)addr;
    char *uri = malloc(128);
    // TODO: probably switch to inet_ntop to handle both ipv4, ipv6
    sprintf(uri, "%s/%s/%d", namespace, inet_ntoa(ip_dst->sin_addr), ip_dst->sin_port);
    printf("uri for pub %s\n", uri);
    socket_uris[sockfd] = uri;
    return orig_connect(sockfd, addr, addrlen);
}


//static ssize_t (*orig_write)(int fd, const void *buf, size_t count);
static int publish(int bw_sock, const char *uri, const void *data, size_t count)
{
    char buf[512+count];
    int written = 0;
    written += sprintf(buf, "publ %010d %010d\n", 0, 2);
    written += sprintf(buf+written, "kv uri %zd\n%s\n", strlen(uri), uri);
    written += sprintf(buf+written, "kv autochain 4\ntrue\n");
    written += sprintf(buf+written, "po 1.0.1.1: %zd\n", count);
    memcpy(buf+written, data, count);
    written += count;
    written += sprintf(buf+written, "\nend\n");
    printf("written: %i\n", written);
    if (orig_write(bw_sock, buf, written) != written)
    {
        printf("Unsuccessfully wrote publish to router\n");
    }
    //printf("%.*s",written,buf);
    return written;
}

//ssize_t read(int fd, void *buf, size_t count)
static int subscribe(int bw_sock, const char *uri, void *data, size_t count)
{
    char buf[512+count];
    int written = 0;
    written += sprintf(buf, "subs %010d %010d\n", 0, 2);
    written += sprintf(buf+written, "kv uri %zd\n%s\n", strlen(uri), uri);
    written += sprintf(buf+written, "kv autochain 4\ntrue\n");
    written += sprintf(buf+written, "kv unpack 4\ntrue\n");
    written += sprintf(buf+written, "\nend\n");
    if (orig_write(bw_sock, buf, written) != written)
    {
        printf("Unsuccessfully wrote subscribe to router\n");
    }

    int numread = 0;
    while (numread == 0)
    {
        numread = orig_read(bw_sock, buf, 1024);
    }
    printf("from bw sock>>>%.*s",numread,buf);
}
