/* http_proxy_util.c */

#include "../include/http_proxy_util.h"

#include "../include/socket_util.h"

/* v1 */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int data_available = 0;

/* v2 */
static pthread_mutex_t buf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t buf_cond = PTHREAD_COND_INITIALIZER;
static int buf_available = 0;

char *alloc_buf(size_t size) {
  char *buf;

  buf = (char *)malloc(size);
  if (chk_alloc_err(buf, "malloc", __func__, __LINE__ - 1) == -1) {
    return NULL;
  }

  return buf;
}

/*
 * typedef struct {
 *   int sockfd;
 *   char *send_buf;
 *   size_t len_send_buf;
 *   char *recv_buf;
 *   size_t len_recv_buf;
 * } HTTPData;
 */
void *async_proxy_send(void *data) {
  HTTPData *http_data = (HTTPData *)data;
  ssize_t bytes_sent;

  if ((bytes_sent = proxy_send(http_data->sockfd, http_data->send_buf,
                               http_data->len_send_buf)) !=
      http_data->len_send_buf) {
    fprintf(stderr, "[ERROR] incomplete send\n");
  }

  return NULL;
}

void *async_proxy_recv(void *data) {
  HTTPData *http_data = (HTTPData *)data;

  pthread_mutex_lock(&buf_mutex);
  http_data->recv_buf =
      proxy_recv(http_data->sockfd, &(http_data->len_recv_buf));

  buf_available = 1;
  pthread_cond_broadcast(&buf_cond);
  pthread_mutex_unlock(&buf_mutex);

  return NULL;
}

void *async_forward_request(void *request) {
  HTTPProxyState *state = (HTTPProxyState *)request;
  ssize_t nb_sent;

  pthread_mutex_lock(&mutex);
  if ((nb_sent = proxy_send(state->origin_sockfd, state->request,
                            state->len_request)) != state->len_request) {
#ifdef DEBUG
    fprintf(stderr, "[ERROR] incomplete request forward (%zd != %zd)\n",
            nb_sent, state->len_request);
    fflush(stderr);
#endif

    close(state->origin_sockfd);

    data_available = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);

    return NULL;
  }

  if ((state->response =
           proxy_recv(state->origin_sockfd, &(state->len_response))) == NULL) {
#ifdef DEBUG
    fprintf(stderr, "[ERROR] failed to receive from origin http server\n");
    fflush(stderr);
#endif
    close(state->origin_sockfd);

    data_available = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);

    return NULL;
  }

  close(state->origin_sockfd);

  data_available = 1;
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&mutex);

  return NULL;
}

void *async_cache_response(void *data) {
  HTTPCache *cache_info = (HTTPCache *)data;

  while (!buf_available) {
    pthread_cond_wait(&buf_cond, &buf_mutex);
  }

  FILE *cache_fp;
  size_t bytes_written;

  fprintf(stderr, "[INFO] fpath = %s\n", cache_info->fpath);
  fprintf(stderr, "[INFO] uri %s (len=%zu)\n", cache_info->uri,
          cache_info->len_response);

  if ((cache_fp = fopen(cache_info->fpath, "wb")) == NULL) {
    fprintf(stderr, "[ERROR] unable to open file: %s\n", cache_info->fpath);
    fprintf(stderr, "  REASON: %s\n", strerror(errno));

    return NULL;
  }

  if ((bytes_written = fwrite(cache_info->response, sizeof(char),
                              cache_info->len_response, cache_fp)) !=
      (size_t)cache_info->len_response) {
    fprintf(stderr, "[ERROR] incomplete write of file '%s'\n", cache_info->fpath);

    fclose(cache_fp);
    return NULL;
  }

  fclose(cache_fp);

  return NULL;
}

void *async_prefetch_response(void *response) {
  HTTPProxyState *state = (HTTPProxyState *)response;

  pthread_mutex_lock(&mutex);
  while (!data_available) {
    pthread_cond_wait(&cond, &mutex);
  }
  pthread_mutex_unlock(&mutex);

  fprintf(stderr, "[%s] i have access to all %zu bytes of the data\n", __func__,
          state->len_response);

  return NULL;
}

/*
 * format:
 *   <method> <uri> <version>\r\n
 *   <header-key>: <header-value>\r\n
 *   ...
 * notes:
 *   - check value of 'Proxy-Connection' header
 *   - forward everything else for now
 */
char *build_request(HTTPCommand *http_cmd, HTTPHeader **http_hdrs,
                    size_t n_hdrs, size_t *len_request) {
  char *request_buf;
  char uri[HTTP_URI_MAX];
  size_t len_uri;

  if ((request_buf = alloc_buf(sizeof(HTTPCommand) +
                               (sizeof(HTTPHeader) * n_hdrs))) == NULL) {
    return NULL;
  }

  *len_request = 0;

  // recreate uri in context of a normal GET request
  len_uri = 0;
  len_uri +=
      snprintf(uri, sizeof(http_cmd->uri), "%s", http_cmd->uri.host.remote_uri);

  for (size_t i = 0; *(http_cmd->uri.query[i].key) != '\0'; ++i) {
    if (i == 0)
      len_uri += snprintf(uri + len_uri, sizeof(char) + 1, "%c", '?');
    else
      len_uri += snprintf(uri + len_uri, sizeof(char) + 1, "%c", '&');

    len_uri += snprintf(uri + len_uri, strlen(http_cmd->uri.query[i].key) + 2,
                        "%s=", http_cmd->uri.query[i].key);
    len_uri += snprintf(uri + len_uri, strlen(http_cmd->uri.query[i].value) + 1,
                        "%s", http_cmd->uri.query[i].value);
  }
  *len_request += snprintf(request_buf, HTTP_MAXLINE_CMD, "%s %s %s\r\n",
                           http_cmd->method, uri, http_cmd->version);

  // recreate header buffer
  char key[HTTP_HEADER_KEY_MAX], value[HTTP_HEADER_VALUE_MAX];
  for (size_t i = 0; i < n_hdrs; ++i) {
    strncpy(key, (*http_hdrs)[i].key, strlen((*http_hdrs)[i].key) + 1);
    strncpy(value, (*http_hdrs)[i].value, strlen((*http_hdrs)[i].value) + 1);

    // forward 'Connection' header with same value
    if (strncmp(key, "Proxy-Connection", strlen(key)) == 0) {
      strncpy(key, "Connection", strlen("Connection") + 1);
    }

    *len_request +=
        snprintf(request_buf + *len_request, strlen(key) + 3, "%s: ", key);
    *len_request += snprintf(request_buf + *len_request, strlen(value) + 3,
                             "%s\r\n", value);
  }

  strncpy(request_buf + *len_request, "\r\n", strlen("\r\n") + 1);
  *len_request += strlen("\r\n");

  return request_buf;
}

int chk_alloc_err(void *mem, const char *allocator, const char *func,
                  int line) {
  if (mem == NULL) {
    fprintf(stderr, "%s failed @%s:%d\n", allocator, func, line);
    return -1;
  }

  return 0;
}

ssize_t find_crlf(char *buf, size_t len_buf) {
  char needle[] = "\r\n";
  size_t needle_idx, len_needle;

  len_needle = strlen(needle);

  for (needle_idx = 0; needle_idx < len_buf; ++needle_idx) {
    if (strncmp(buf + needle_idx, needle, len_needle) == 0) {
      return needle_idx;
    }
  }

  return -1;
}

void handle_connection(int client_sockfd) {
  pthread_t tid_recv, tid_forward_request, tid_forward_response, tid_cache_response;;

  HTTPData data;
  HTTPCommand http_cmd;
  HTTPHeader *http_hdrs;

  size_t n_hdrs, len_uri, len_request;
  int parse_rc, origin_sockfd;

  HTTPCache cache_info;
  unsigned long hash;
  char *str_hash;

  // recv from client
  data.sockfd = client_sockfd;
  if (pthread_create(&tid_recv, NULL, async_proxy_recv, &data) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  pthread_join(tid_recv, NULL);
  if (data.recv_buf == NULL) {
    exit(EXIT_FAILURE);
  }

  http_hdrs = malloc(HTTP_HEADERS_MAX * sizeof(HTTPHeader));
  chk_alloc_err(http_hdrs, "malloc", __func__, __LINE__ - 1);

  if ((parse_rc = parse_request(data.recv_buf, data.len_recv_buf, &http_cmd,
                                http_hdrs, &n_hdrs)) != 0) {
    if (send_err(data.sockfd, parse_rc) < 0) {
      fprintf(stderr, "[ERROR] unable to send error (%d) response\n", parse_rc);
    }

    free(data.recv_buf);
    free(http_hdrs);

    exit(EXIT_SUCCESS);
  }

  free(data.recv_buf);

  // connect to origin server
  if ((origin_sockfd = connection_sockfd(http_cmd.uri.host.hostname,
                                         http_cmd.uri.host.port)) == -1) {
    // could not create socket to connect to origin server
    if (send_err(client_sockfd, HTTP_NOT_FOUND_CODE) < 0) {
      free(http_hdrs);
      exit(EXIT_FAILURE);  // server error
    }

    free(http_hdrs);

    return;
  }

  data.sockfd = origin_sockfd;
  data.send_buf = build_request(&http_cmd, &http_hdrs, n_hdrs, &len_request);
  data.len_send_buf = len_request;

  // send to origin server
  if (pthread_create(&tid_forward_request, NULL, async_proxy_send, &data) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  // recv from origin server
  if (pthread_create(&tid_recv, NULL, async_proxy_recv, &data) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }
  pthread_join(tid_recv, NULL);
  free(data.send_buf);

  // send response to client
  data.sockfd = client_sockfd;
  data.send_buf = data.recv_buf;
  data.len_send_buf = data.len_recv_buf;
  if (pthread_create(&tid_forward_response, NULL, async_proxy_send, &data) <
      0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  len_uri = 0;
  len_uri += snprintf(cache_info.uri, sizeof(http_cmd.uri), "%s",
                      http_cmd.uri.host.remote_uri);

  // query
  for (size_t i = 0; *(http_cmd.uri.query[i].key) != '\0'; ++i) {
    if (i == 0)
      len_uri +=
          snprintf(cache_info.uri + len_uri, sizeof(char) + 1, "%c", '?');
    else
      len_uri +=
          snprintf(cache_info.uri + len_uri, sizeof(char) + 1, "%c", '&');

    len_uri += snprintf(cache_info.uri + len_uri,
                        strlen(http_cmd.uri.query[i].key) + 2,
                        "%s=", http_cmd.uri.query[i].key);
    len_uri += snprintf(cache_info.uri + len_uri,
                        strlen(http_cmd.uri.query[i].value) + 1, "%s",
                        http_cmd.uri.query[i].value);
  }

  str_hash = alloc_buf(HASH_LEN + 1);

  hash = hash_djb2(cache_info.uri);
  snprintf(str_hash, HASH_LEN, "%lx", hash);

  strncpy(cache_info.fpath, str_hash, strlen(str_hash));
  strnins(cache_info.fpath, CACHE_BASE, strlen(CACHE_BASE));

  cache_info.response = data.recv_buf;
  cache_info.len_response = data.len_recv_buf;

  if (pthread_create(&tid_cache_response, NULL, async_cache_response,
                     &cache_info) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  // prefetch response

  pthread_join(tid_forward_request, NULL);
  pthread_join(tid_forward_response, NULL);
  pthread_join(tid_cache_response, NULL);

  free(str_hash);
  free(data.recv_buf);
  free(http_hdrs);
}

unsigned long hash_djb2(char *s) {
  unsigned long hash = 5381;
  int c;

  while ((c = *s++)) {
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }

  return hash;
}

ssize_t http_readline(char *buf, size_t len_buf, char *out_buf) {
  ssize_t needle_idx;

  if ((needle_idx = find_crlf(buf, len_buf)) <= 0) {  // last CRLF or error
    return needle_idx;
  }

  strncpy(out_buf, buf, needle_idx);
  out_buf[needle_idx] = '\0';

  return needle_idx + 2;  // move past CRLF
}

const char *http_status_msg(int http_status_code) {
  switch (http_status_code) {
    case HTTP_BAD_REQUEST_CODE:
      return "Bad Request";
    case HTTP_NOT_FOUND_CODE:
      return "Not Found";
    default:
      fprintf(stderr, "[FATAL] (%s:%d) this code should be unreachable\n",
              __func__, __LINE__ - 1);
      exit(EXIT_FAILURE);
  }
}

/*
    typedef struct {
      char method[HTTP_METHOD_MAX];
      HTTPUri uri;
      char version[HTTP_VERSION_MAX];
    } HTTPCommand;
 */
ssize_t parse_command(char *client_buf, size_t nb_recv, HTTPCommand *http_cmd) {
  ssize_t buf_offset, tmp_buf_offset, skip;
  char line[HTTP_MAXLINE_CMD];
  size_t line_len;
  char uri[HTTP_URI_MAX];

  skip = http_readline(client_buf, nb_recv, line);
  if (skip == -1 || (size_t)skip == nb_recv) {
    // CRLF does not exist within bounds of client request buffer [0, nb_recv]
    return -1;
  }

  line_len = strlen(line);

  if ((tmp_buf_offset = read_until(line, line_len, ' ', http_cmd->method,
                                   sizeof(http_cmd->method))) == -1) {
    return -1;
  }
  buf_offset = tmp_buf_offset;

  if ((tmp_buf_offset = read_until(line + buf_offset, line_len - buf_offset,
                                   ' ', uri, sizeof(uri))) == -1) {
    return -1;
  }
  buf_offset += tmp_buf_offset;

  if ((tmp_buf_offset = parse_uri(uri, sizeof(uri), &(http_cmd->uri))) == -1) {
    return -1;
  }
  // no need to increment `buf_offset`, did 4 lines above

  if ((tmp_buf_offset =
           read_until(line + buf_offset, line_len - buf_offset, '\0',
                      http_cmd->version, sizeof(http_cmd->version))) == -1) {
    return -1;
  }
  buf_offset += tmp_buf_offset;

  return buf_offset + 1;
}

/*
    typedef struct {
      char key[HTTP_HEADER_KEY_MAX];
      char value[HTTP_HEADER_VALUE_MAX];
    } HTTPHeader;
 */
ssize_t parse_headers(char *read_buf, size_t max_read, HTTPHeader *http_hdrs,
                      size_t *n_hdrs) {
  char line_buf[HTTP_MAXLINE_HDR + 1];
  ssize_t local_offset, global_offset, i, j;

  global_offset = 0;
  local_offset = 0;
  *n_hdrs = 0;
  while ((local_offset = http_readline(read_buf, max_read, line_buf)) > 0) {
    i = 0;
    j = read_until(line_buf + i, max_read - global_offset, ':',
                   http_hdrs[*n_hdrs].key, HTTP_HEADER_KEY_MAX);
    if (j == -1) return -1;

    i += j;

    j = read_until(line_buf + i, max_read - global_offset - i, '\0',
                   http_hdrs[*n_hdrs].value, HTTP_HEADER_VALUE_MAX);
    if (j == -1) return -1;

    i += j;

    read_buf += local_offset;
    global_offset += local_offset;
    if (*n_hdrs == HTTP_HEADERS_MAX - 1) {
      return -1;
    }
    (*n_hdrs)++;
  }

  // move past final CRLF
  return local_offset < 0 ? local_offset : global_offset + 2;
}

/*
    typedef struct {
      char hostname[HTTP_HOSTNAME_MAX];
      char port[HTTP_PORT_MAX_DIGITS];
      char remote_uri[HTTP_REMOTE_MAX];
    } HTTPHost;
 */
ssize_t parse_host(char *buf, size_t len_buf, HTTPHost *http_host) {
  ssize_t buf_offset;

  // port was specified
  if ((buf_offset = read_until(buf, len_buf, ':', http_host->hostname,
                               sizeof(http_host->hostname))) != -1) {
    buf_offset += read_until(buf + buf_offset, len_buf - buf_offset, '/',
                             http_host->port, sizeof(http_host->port));
  } else {  // port was not specified
    buf_offset = read_until(buf, len_buf, '/', http_host->hostname,
                            sizeof(http_host->hostname));
    strcpy(http_host->port, "80");
  }

  if ((buf_offset += read_until(buf + buf_offset, len_buf - buf_offset, '?',
                                http_host->remote_uri,
                                sizeof(http_host->remote_uri))) == -1) {
    buf_offset += 1;  // reset, no query parameters
  }

  return buf_offset;
}

/*
    typedef struct {
      char key[HTTP_PARAM_KEY_MAX];
      char value[HTTP_PARAM_VALUE_MAX];
    } HTTPQuery;
 */
ssize_t parse_query(char *buf, HTTPQuery *http_query) {
  char *param_sep = "&", *keyval_sep = "=";
  char *key_saveptr, *key, *value_saveptr, *value;
  ssize_t buf_offset;
  size_t i;

  memset(http_query, 0, sizeof(http_query) * HTTP_QUERIES_MAX);
  key = strtok_r(buf, param_sep, &key_saveptr);
  buf_offset = 0;
  i = 0;

  while (key != NULL) {
    value = strtok_r(key, keyval_sep, &value_saveptr);
    while (value != NULL) {
      value = strtok_r(NULL, keyval_sep, &value_saveptr);
      if (value) {
        size_t key_len = strlen(key);
        size_t value_saveptr_len = strlen(value);

        strncpy(http_query[i].key, key, strlen(key));
        buf_offset += key_len + 1;  // for '='

        strncpy(http_query[i].value, value, strlen(value));
        buf_offset += value_saveptr_len;  // for '&'

        i++;
      }
    }
    key = strtok_r(NULL, param_sep, &key_saveptr);
  }

  return buf_offset > 0 ? buf_offset : -1;
}

ssize_t parse_request(char *client_buf, ssize_t nb_recv, HTTPCommand *http_cmd,
                      HTTPHeader *http_hdrs, size_t *n_hdrs) {
  int buf_offset, tmp_buf_offset, http_status;

  if ((tmp_buf_offset = parse_command(client_buf, nb_recv, http_cmd)) == -1) {
    return HTTP_BAD_REQUEST_CODE;
  }
  buf_offset = tmp_buf_offset;

  if ((http_status = validate_method(http_cmd->method)) != 0) {
    return HTTP_BAD_REQUEST_CODE;
  }

  // more data in headers, so validate command first (could return early)
  // TODO: not sure if i need to return an offset from `parse_headers`
  if ((tmp_buf_offset += parse_headers(
           client_buf + buf_offset, nb_recv - buf_offset, http_hdrs, n_hdrs)) ==
      -1) {
    return HTTP_BAD_REQUEST_CODE;
  }

  // TODO: why would we need to validate headers?
  // if ((http_status = validate_headers(http_hdrs, n_hdrs)) > 0) {
  //   fprintf(stderr, "[ERROR] invalid headers: %d %s\n", http_status,
  //           http_status_msg(http_status));
  //
  //   return http_status;
  // }

  return 0;
}

/*
    typedef struct {
      HTTPHost host;
      HTTPQuery *query;
    } HTTPUri;
 */
// TODO: error when using https instead of http as scheme
ssize_t parse_uri(char *buf, size_t len_buf, HTTPUri *http_uri) {
  ssize_t skip;

  buf += skip_scheme(buf);

  skip = parse_host(buf, len_buf, &(http_uri->host));
  skip += parse_query(buf + skip, http_uri->query);

  return skip;
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

  set_timeout(sockfd, 0, RCVTIMEO_USEC);

  total_nb_recv = 0;
  num_reallocs = 1;
  while ((*nb_recv = recv(sockfd, recv_buf + total_nb_recv, RECV_CHUNK_SZ, 0)) >
         0) {
    total_nb_recv += (size_t)*nb_recv;
    // allocate more memory
    if (*nb_recv == RECV_CHUNK_SZ && total_nb_recv == bytes_alloced) {
      realloc_sz = total_nb_recv + (RECV_CHUNK_SZ * (int)pow(2, num_reallocs));
      if ((recv_buf = realloc_buf(recv_buf, realloc_sz)) == NULL) {
        free(recv_buf);  // avoid memory leak of previous buffer on `realloc`
                         // failure
        return NULL;
      }
      num_reallocs++;
      bytes_alloced = realloc_sz;
    }
  }

  *nb_recv = total_nb_recv;

  if (total_nb_recv == 0) {  // timeout
    perror("recv");
    free(recv_buf);
    return NULL;
  }

#ifdef DEBUG
  fprintf(stderr, "[%s] received %zd bytes\n", __func__, *nb_recv);
  fflush(stderr);
#endif

  return recv_buf;
}

ssize_t proxy_send(int sockfd, char *send_buf, size_t len_send_buf) {
  ssize_t nb_sent;

  fprintf(stderr, "[%s] sending %zu bytes\n", __func__, len_send_buf);
  if ((nb_sent = send(sockfd, send_buf, len_send_buf, 0)) < 0) {
    perror("send");
    return -1;
  }

  return nb_sent;
}

char *read_file(const char *fpath, size_t *nb_read) {
  char *out_buf;
  FILE *fp;
  struct stat st;

  if ((fp = fopen(fpath, "rb")) == NULL) {
    // server error
    return NULL;
  }

  if (stat(fpath, &st) < 0) {
    // server error
    fclose(fp);
    return NULL;
  }

  out_buf = alloc_buf(st.st_size);

  if ((*nb_read = fread(out_buf, 1, st.st_size, fp)) < (size_t)st.st_size) {
    fclose(fp);

    return NULL;
  }

  fclose(fp);

  return out_buf;
}

ssize_t read_until(char *haystack, size_t len_haystack, char end, char *sink,
                   size_t len_sink) {
  // move past space between ':' and header value
  while (isspace(*haystack)) {
    haystack += 1;
  }

  // up to the length of the input buffer, read as many characters that are
  // allowed in `sink`
  size_t i;
  for (i = 0; i < len_haystack && i < len_sink && haystack[i] != end; ++i) {
    sink[i] = haystack[i];
  }

  // if nothing found, bad request
  if (haystack[i] != end) {
    return -1;
  }

  sink[i] = '\0';

  // move pointer to next field of http status line for all fields but the uri
  // when end='/', retain current position
  return end != '/' ? (ssize_t)i + 1 : (ssize_t)i;
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

int send_err(int sockfd, size_t http_status_code) {
  const char *err_file;
  char *send_buf, *file_contents;
  char headers[HTTP_MAX_ERR_HEADER + 1];
  size_t nb_read, len_send_buf, len_headers;

  switch (http_status_code) {
    case HTTP_BAD_REQUEST_CODE:
      err_file = HTML_400;
      break;
    case HTTP_NOT_FOUND_CODE:
      err_file = HTML_404;
      break;
    default:
      fprintf(stderr, "[FATAL] this code should be unreachable\n");
  }

  if ((file_contents = read_file(err_file, &nb_read)) == NULL) {
#ifdef DEBUG
    fprintf(stderr, "[INFO] unable to read file %s\n", err_file);
#endif
    return -1;
  }

  // build headers
  snprintf(headers, HTTP_MAX_ERR_HEADER,
           "HTTP/1.1 %zu %s\r\n"
           "Content-Type: text/html\r\n"
           "Content-Length: %zu\r\n"
           "\r\n",
           http_status_code, http_status_msg(http_status_code), nb_read);

  len_headers = strlen(headers);

  if ((send_buf = alloc_buf(len_headers + nb_read + 1)) == NULL) {
    fprintf(stderr, "[FATAL] child process ran out of memory\n");
    exit(EXIT_FAILURE);
  }

  strncpy(send_buf, headers, len_headers + 1);  // +1 to copy '\0', needed by
                                                // `strncat`
  strncat(send_buf, file_contents, nb_read);
  len_send_buf = len_headers + nb_read;

  pthread_t tid_send_err;

  HTTPData data;
  data.sockfd = sockfd;
  data.send_buf = send_buf;
  data.len_send_buf = len_send_buf;

  if (pthread_create(&tid_send_err, NULL, async_proxy_send, &data) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  pthread_join(tid_send_err, NULL);

  free(file_contents);
  free(data.send_buf);

  return 0;
}

size_t skip_scheme(char *buf) {
  size_t i, len_buf;

  i = 0;
  len_buf = strlen(buf);
  while (i < len_buf && buf[i] != '/') {
    i++;
  }

  return i == len_buf ? 0 : i + 2;  // move past second '/'
}

size_t strnins(char *dst, const char *src, size_t n) {
  size_t src_len, dst_len;

  src_len = strlen(src);
  dst_len = strlen(dst);

  if (n > src_len) {
    n = src_len;
  }

  char tmp[dst_len + n + 1];
  strncpy(tmp, dst, dst_len);
  strncpy(dst, src, src_len);
  strncpy(dst + src_len, tmp, dst_len);

  return n;
}

int validate_method(char *method) {
  return strncmp(method, "GET", strlen("GET"));
}

// === DEBUG FUNCTIONS ===
void print_command(HTTPCommand http_cmd) {
  fprintf(stderr, "\nHTTPCommand {\n");

  fprintf(stderr, "  Method: %s\n", http_cmd.method);
  fprintf(stderr, "  HTTPUri {\n");
  fprintf(stderr, "    HTTPHost {\n");
  fprintf(stderr, "      hostname: %s\n", http_cmd.uri.host.hostname);
  fprintf(stderr, "      port: %s\n", http_cmd.uri.host.port);
  fprintf(stderr, "      remote_uri: %s\n", http_cmd.uri.host.remote_uri);
  fprintf(stderr, "    }\n");
  fprintf(stderr, "    HTTPQuery {\n");

  for (size_t i = 0; *(http_cmd.uri.query[i].key) != '\0'; ++i) {
    fprintf(stderr, "      key: %s\n", http_cmd.uri.query[i].key);
    fprintf(stderr, "      value: %s\n", http_cmd.uri.query[i].value);
  }

  fprintf(stderr, "    }\n");
  fprintf(stderr, "  }\n");
  fprintf(stderr, "  version: %s\n", http_cmd.version);
  fprintf(stderr, "}\n");

  fflush(stderr);
}

void print_header(HTTPHeader http_hdr) {
  fprintf(stderr, "  %s: %s\n", http_hdr.key, http_hdr.value);
}

void print_headers(HTTPHeader *http_hdrs, size_t n_hdrs) {
  fprintf(stderr, "\nHTTPHeaders {\n");
  for (size_t i = 0; i < n_hdrs; ++i) {
    print_header(http_hdrs[i]);
  }
  fprintf(stderr, "}\n");
}

void print_request(HTTPHeader *http_hdrs, size_t n_hdrs, HTTPCommand http_cmd) {
  fprintf(stderr, "[INFO] received request:\n");
  print_command(http_cmd);
  print_headers(http_hdrs, n_hdrs);
}
