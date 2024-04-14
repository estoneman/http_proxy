#include "../include/async.h"

#include "../include/http_proxy_util.h"
#include "../include/socket_util.h"

/* thread access management */
static pthread_mutex_t file_io_mutex =
    PTHREAD_MUTEX_INITIALIZER;  // file write/read
static pthread_mutex_t net_io_mutex =
    PTHREAD_MUTEX_INITIALIZER;  // socket send/recv
static pthread_rwlock_t pc_rwlock =
    PTHREAD_RWLOCK_INITIALIZER;  // proxy cache buffer access
static pthread_rwlock_t sb_rwlock =
    PTHREAD_RWLOCK_INITIALIZER;  // socket buffer access

void *async_cache_response(void *data) {
  ProxyCache *proxy_cache = (ProxyCache *)data;

  FILE *cache_fp;
  size_t bytes_written;

  pthread_mutex_lock(&file_io_mutex);
  if ((cache_fp = fopen(proxy_cache->fpath, "wb")) == NULL) {
    fprintf(stderr, "[ERROR] unable to open file: %s\n", proxy_cache->fpath);
    fprintf(stderr, "  REASON: %s\n", strerror(errno));

    return NULL;
  }

  pthread_rwlock_rdlock(&pc_rwlock);
  fprintf(stderr, "[%s] caching %s\n", __func__, proxy_cache->fpath);
  if ((bytes_written = fwrite(proxy_cache->data, sizeof(char),
                              proxy_cache->len_data, cache_fp)) !=
      (size_t)proxy_cache->len_data) {
    fprintf(stderr, "[ERROR] incomplete write of file '%s'\n",
            proxy_cache->fpath);

    fclose(cache_fp);
    return NULL;
  }
  pthread_rwlock_unlock(&pc_rwlock);

  fclose(cache_fp);
  pthread_mutex_unlock(&file_io_mutex);

  return NULL;
}

void *async_prefetch_response(void *arg) {
  SocketBuffer *socket_buf = (SocketBuffer *)arg;

  char **urls, *request;
  size_t n_urls;
  ssize_t skip, total_skip, len_request;
  int origin_sockfd;

  skip = total_skip = 0;

  pthread_rwlock_rdlock(&sb_rwlock);

  while ((skip = find_crlf(socket_buf->data + total_skip,
                           socket_buf->len_data - total_skip)) > 0) {
    total_skip += skip + 2;  // + 2 to move past CRLF
  }

  if (total_skip == 0) {  // no data to read
    return NULL;
  }

  total_skip += 2;  // move past final CRLF

  // no data, e.g., server replied with 301 Moved Permanently
  if ((urls = get_urls(socket_buf->data + total_skip,
                       socket_buf->len_data - total_skip, &n_urls)) == NULL) {
    return NULL;
  }

  pthread_rwlock_unlock(&sb_rwlock);

  pthread_t cache_threads[n_urls];
  pthread_t send_threads[n_urls];
  pthread_t recv_threads[n_urls];

  SocketBuffer prefetch_sb_recv;
  SocketBuffer prefetch_sb_send;
  ProxyCache pc_write[n_urls];

  HTTPUri uris[n_urls];
  unsigned long hash;

  if ((request = alloc_buf(HTTP_MAXLINE_CMD)) == NULL) {
    fprintf(stderr, "[FATAL] out of memory\n");

    exit(EXIT_FAILURE);
  }

  for (size_t i = 0; i < n_urls; ++i) {
    // offset thread ids
    cache_threads[i] = i + n_urls;
    send_threads[i] = i + (n_urls * 2);
    recv_threads[i] = i + (n_urls * 3);

    parse_uri(urls[i], strlen(urls[i]), &uris[i]);

    if ((origin_sockfd = connection_sockfd(uris[i].host.hostname,
                                           uris[i].host.port)) == -1) {
      continue;
    }

    /*
     * > GET /~rek/Grad_Nets/Spring2013/Program0_S13.pdf HTTP/1.1
       > Host: web.cs.wpi.edu
       > User-Agent: curl/7.81.0
       > Accept: *\* -- yes, it should be a forward slash, but C comments..
     */
    len_request = snprintf(request, HTTP_MAXLINE_CMD, "GET %s HTTP/1.1\r\n"
                                                      "Host: %s\r\n"
                                                      "Accept: */*\r\n"
                                                      "\r\n",
                           uris[i].host.remote_uri, uris[i].host.hostname);
    hash = hash_djb2(urls[i]);

    snprintf(pc_write[i].fpath, HASH_LEN, "%0*lx", HASH_LEN - 1, hash);
    strnins(pc_write[i].fpath, CACHE_BASE, sizeof(CACHE_BASE));

#ifdef DEBUG
    fprintf(stderr, "[%s] resolved %s to file %s\n", __func__, urls[i],
            pc_write[i].fpath);
    fflush(stderr);
#endif

    prefetch_sb_send.sockfd = origin_sockfd;
    prefetch_sb_send.data = request;
    prefetch_sb_send.len_data = len_request;

    if (pthread_create(&send_threads[i], NULL, async_proxy_send,
                       &prefetch_sb_send) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);

      continue;
    }

    prefetch_sb_recv.sockfd = origin_sockfd;

    if (pthread_create(&recv_threads[i], NULL, async_proxy_recv,
                       &prefetch_sb_recv) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);

      continue;
    }
    pthread_join(recv_threads[i], NULL);
    close(prefetch_sb_recv.sockfd);

    // allocate space for cache buffer
    if ((pc_write[i].data = alloc_buf(prefetch_sb_recv.len_data)) == NULL) {
      fprintf(stderr, "[FATAL] out of memory\n");

      exit(EXIT_FAILURE);
    }

    memcpy(pc_write[i].data, prefetch_sb_recv.data,
           prefetch_sb_recv.len_data);
    pc_write[i].len_data = prefetch_sb_recv.len_data;

    free(prefetch_sb_recv.data);  // no longer in use

    if (pthread_create(&cache_threads[i], NULL, async_cache_response,
                       &pc_write[i]) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);
      close(origin_sockfd);

      continue;
    }
  }

  for (size_t i = 0; i < n_urls; ++i) {
    if (pthread_kill(cache_threads[i], 0) == 0) {  // check if thread is alive
      pthread_join(cache_threads[i], NULL);
    }

    free(pc_write[i].data);

    if (pthread_kill(send_threads[i], 0) == 0) {
      pthread_join(send_threads[i], NULL);
    }
  }

  for (size_t i = 0; i < MAX_URLS; ++i) {
    free(urls[i]);
  }
  free(urls);
  free(request);

  return NULL;
}

void *async_proxy_recv(void *arg) {
  SocketBuffer *socket_buf = (SocketBuffer *)arg;

  pthread_mutex_lock(&net_io_mutex);
  pthread_rwlock_wrlock(&sb_rwlock);

  socket_buf->data = proxy_recv(socket_buf->sockfd, &(socket_buf->len_data));

#ifdef DEBUG
  fprintf(stderr, "[%s] received %zd bytes\n", __func__, socket_buf->len_data);
  fflush(stderr);
#endif

  pthread_rwlock_unlock(&sb_rwlock);
  pthread_mutex_unlock(&net_io_mutex);

  return NULL;
}

void *async_proxy_send(void *arg) {
  SocketBuffer *socket_buf = (SocketBuffer *)arg;
  ssize_t bytes_sent;

  pthread_mutex_lock(&net_io_mutex);
  pthread_rwlock_rdlock(&sb_rwlock);

  if ((bytes_sent = proxy_send(socket_buf->sockfd, socket_buf->data,
                               socket_buf->len_data)) != socket_buf->len_data) {
    fprintf(stderr, "[ERROR] incomplete send\n");
  }

#ifdef DEBUG
  fprintf(stderr, "[%s] sent %zd bytes\n", __func__, bytes_sent);
  fflush(stderr);
#endif

  pthread_rwlock_unlock(&sb_rwlock);
  pthread_mutex_unlock(&net_io_mutex);

  return NULL;
}

void *async_read_cache(void *arg) {
  ProxyCache *pc_read = (ProxyCache *)arg;

  pthread_mutex_lock(&file_io_mutex);
  pthread_rwlock_wrlock(&pc_rwlock);

  pc_read->data = read_file(pc_read->fpath, (size_t *)&(pc_read->len_data));

#ifdef DEBUG
  fprintf(stderr, "[%s] read %zu bytes from %s\n", __func__, pc_read->len_data,
          pc_read->fpath);
#endif

  pthread_rwlock_unlock(&pc_rwlock);
  pthread_mutex_unlock(&file_io_mutex);

  return NULL;
}
