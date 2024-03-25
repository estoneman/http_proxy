#include "../include/http_proxy_util.h"
#include "../include/socket_util.h"

char *alloc_buf(size_t size) {
  char *buf;

  buf = (char *)malloc(size);
  if (chk_alloc_err(buf, "malloc", __func__, __LINE__ - 1) == -1) {
    return NULL;
  }

  return buf;
}

char *realloc_buf(char *buf, size_t size) {
  char *tmp_buf;

  tmp_buf = realloc(buf, size);
  if (chk_alloc_err(tmp_buf, "realloc", __func__, __LINE__ - 1) == -1) {
    return NULL;
  }

  buf = tmp_buf;

  return buf;
}

int chk_alloc_err(void *mem, const char *allocator, const char *func,
                   int line) {
  if (mem == NULL) {
    fprintf(stderr, "%s failed @%s:%d\n", allocator, func, line);
    return -1;
  }

  return 0;
}

void handle_connection(int sockfd) {
  char *recv_buf;
  ssize_t nb_recv;
  
  if ((recv_buf = proxy_recv(sockfd, &nb_recv)) == NULL) {
    exit(EXIT_FAILURE);
  }
  
  fprintf(stderr, "[INFO] received %zd bytes\n", nb_recv);

  free(recv_buf);
}

char *proxy_recv(int sockfd, ssize_t *nb_recv) {
  char *recv_buf;
  size_t total_nb_recv, num_reallocs, bytes_alloced, realloc_sz;

  if ((recv_buf = alloc_buf(RECV_CHUNK_SZ)) == NULL) {
    fprintf(stderr, "failed to allocate receive buffer (%s:%d)", __func__,
            __LINE__ - 1);
    return NULL;
  }

  bytes_alloced = RECV_CHUNK_SZ;

  set_timeout(sockfd);

  total_nb_recv = 0;
  num_reallocs = 1;
  while ((*nb_recv = recv(sockfd, recv_buf + total_nb_recv, RECV_CHUNK_SZ, 0)) > 0) {
    total_nb_recv += (size_t)*nb_recv;
    // allocate more memory
    if (*nb_recv == RECV_CHUNK_SZ && total_nb_recv == bytes_alloced) {
      realloc_sz = total_nb_recv + (RECV_CHUNK_SZ * (int)pow(2, num_reallocs));
      if ((recv_buf = realloc_buf(recv_buf, realloc_sz)) == NULL) {
        return NULL;
      }
      num_reallocs++;
      bytes_alloced = realloc_sz;
    }
  }

  if (*nb_recv < 0) {
    // TODO: timeout occurred, not sure what I should do here
  }

  *nb_recv = total_nb_recv;

  return recv_buf;
}
