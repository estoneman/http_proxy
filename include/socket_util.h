#ifndef SOCKET_UTIL_H_
#define SOCKET_UTIL_H_

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/http_proxy_util.h"

#define MIN_PORT 1024
#define MAX_PORT 65535

#define MAX_RECV_SZ (RECV_CHUNK_SZ * 1000)
#define RCVTIMEO_SEC 0
#define RCVTIMEO_USEC (500 * 1000)
#define RECV_CHUNK_SZ 4096

int connection_sockfd(const char *, const char *);
int listen_sockfd(const char *);
void *get_inetaddr(struct sockaddr *);
void get_ipstr(char *, struct sockaddr *);
int is_blocked(const char *hostname, struct addrinfo *);
int is_valid_port(const char *);
char *proxy_recv(int, ssize_t *);
ssize_t proxy_send(int, char *, size_t);
void set_timeout(int, long, long);

// debug

#endif  // SOCKET_UTIL_H_
