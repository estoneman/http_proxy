#ifndef SOCKET_UTIL_H_
#define SOCKET_UTIL_H_

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
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

#define BACKLOG 10
#define MIN_PORT 1024
#define MAX_PORT 65535

int fill_socket_info(struct addrinfo **, struct addrinfo **, const char *);
void *get_inetaddr(struct sockaddr *);
void get_ipstr(char *, struct sockaddr *);
int is_valid_port(const char *);
void set_timeout(int);

// debug

#endif  // SOCKET_UTIL_H_
