#ifndef HTTP_PROXY_UTIL_H_
#define HTTP_PROXY_UTIL_H_

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#define RCVTIMEO_USEC (300 * 1000)
#define RECV_CHUNK_SZ 1024
#define MAX_RECV_SZ (RECV_CHUNK_SZ * 1000)

char *alloc_buf(size_t);
int chk_alloc_err(void *, const char *, const char *, int);
void handle_connection(int);
char *proxy_recv(int, ssize_t *);

#endif  // HTTP_PROXY_UTIL_H_
