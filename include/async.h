#ifndef ASYNC_H_
#define ASYNC_H_

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "../include/http_proxy_util.h"

typedef struct {
  int sockfd;
  char *data;
  ssize_t len_data;
} SocketBuffer;

typedef struct {
  char fpath[HTTP_FNAME_MAX];
  char uri[HTTP_URI_MAX];
  char *data;
  ssize_t len_data;
} ProxyCache;

void *async_cache_response(void *);
void *async_prefetch_response(void *);
void *async_proxy_recv(void *);
void *async_proxy_send(void *);
void *async_read_cache(void *arg);

#endif  // ASYNC_H_
