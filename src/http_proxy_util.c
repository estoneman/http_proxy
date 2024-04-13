/* http_proxy_util.c */

#include "../include/http_proxy_util.h"

#include "../include/async.h"
#include "../include/socket_util.h"

char *alloc_buf(size_t size) {
  char *buf;

  buf = (char *)malloc(size);
  if (chk_alloc_err(buf, "malloc", __func__, __LINE__ - 1) == -1) {
    return NULL;
  }

  return buf;
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

  if ((request_buf = alloc_buf(sizeof(HTTPCommand) +
                               (sizeof(HTTPHeader) * n_hdrs))) == NULL) {
    return NULL;
  }

  *len_request = 0;

  // recreate uri in context of a normal GET request
  rebuild_uri(uri, http_cmd, 0);
  *len_request += snprintf(request_buf, HTTP_MAXLINE_CMD, "%s %s %s\r\n",
                           http_cmd->method, uri, http_cmd->version);

  // recreate header buffer
  char key[HTTP_HEADER_KEY_MAX + 1], value[HTTP_HEADER_VALUE_MAX + 1];
  for (size_t i = 0; i < n_hdrs; ++i) {
    strncpy(key, (*http_hdrs)[i].key, HTTP_HEADER_KEY_MAX);
    strncpy(value, (*http_hdrs)[i].value, HTTP_HEADER_VALUE_MAX);

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

char **get_urls(char *html, size_t len_html, size_t *n_urls) {
  char **urls, tmp_buf[HTTP_SCHEME_MAX];
  size_t html_ptr, url_ptr;
  unsigned long scheme_hash;

  if ((urls = (char **)malloc(MAX_URLS * sizeof(char *))) == NULL) {
    fprintf(stderr, "[FATAL] out of memory\n");

    exit(EXIT_FAILURE);
  }

  for (size_t i = 0; i < MAX_URLS; ++i) {
    if ((urls[i] = alloc_buf(MAX_URL_SZ + 1)) == NULL) {
      fprintf(stderr, "[FATAL] out of memory\n");

      exit(EXIT_FAILURE);
    }
  }

  scheme_hash = hash_djb2(HTTP_SCHEME);
  html_ptr = 0;
  *n_urls = 0;

  while (html_ptr < len_html - strlen(HTTP_SCHEME) - 1) {
    url_ptr = 0;
    strncpy(tmp_buf, html + html_ptr, strlen(HTTP_SCHEME));
    if (hash_djb2(tmp_buf) == scheme_hash) {
      while (html_ptr < len_html &&
             (html[html_ptr] != '"' && html[html_ptr] != ' ' &&
              html[html_ptr] != '\'' && html[html_ptr] != ')' &&
              html[html_ptr] != '\n')) {
        urls[*n_urls][url_ptr] = html[html_ptr];

        url_ptr++;
        html_ptr++;
      }
      urls[*n_urls][url_ptr] = '\0';
      *n_urls = *n_urls + 1;

      continue;
    }

    html_ptr++;
  }

  return urls;
}

void handle_connection(int client_sockfd, int cache_timeout) {
  pthread_t tid_recv, tid_forward_request, tid_forward_response,
      tid_cache_response, tid_read_cache, tid_prefetch_response;

  SocketBuffer sb_send;
  SocketBuffer sb_recv;
  HTTPCommand http_cmd;
  HTTPHeader *http_hdrs;

  size_t n_hdrs, len_request;
  int parse_rc, origin_sockfd, free_recv_buf;

  ProxyCache pc_read;
  ProxyCache pc_write;
  char uri[HTTP_URI_MAX];
  unsigned long hash;
  int access;
  struct stat st_cache;
  struct timespec ts_current;
  long int diff;
  pid_t chld_pid;

  chld_pid = getpid();
  // recv from client
  sb_recv.sockfd = client_sockfd;
  set_timeout(client_sockfd, RCVTIMEO_SEC, RCVTIMEO_USEC);

  if (pthread_create(&tid_recv, NULL, async_proxy_recv, &sb_recv) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  pthread_join(tid_recv, NULL);
  if (sb_recv.data == NULL) {
    exit(EXIT_FAILURE);
  }

  http_hdrs = malloc(HTTP_HEADERS_MAX * sizeof(HTTPHeader));
  chk_alloc_err(http_hdrs, "malloc", __func__, __LINE__ - 1);

  if ((parse_rc = parse_request(sb_recv.data, sb_recv.len_data, &http_cmd,
                                http_hdrs, &n_hdrs)) != 0) {
    if (send_err(sb_recv.sockfd, parse_rc) < 0) {
      fprintf(stderr, "[ERROR] unable to send error (%d) response\n", parse_rc);
    }

    free(sb_recv.data);
    free(http_hdrs);

    exit(EXIT_SUCCESS);
  }
  free(sb_recv.data);

  rebuild_uri(uri, &http_cmd, 1);
  hash = hash_djb2(uri);

  snprintf(pc_read.fpath, HASH_LEN, "%0*lx", HASH_LEN - 1, hash);
  strnins(pc_read.fpath, CACHE_BASE, sizeof(CACHE_BASE));

#ifdef DEBUG
  fprintf(stderr, "[%s:%d] resolved fpath of %s = %s\n", __func__, chld_pid,
          uri, pc_read.fpath);
  fflush(stderr);
#endif

  diff = -1;
  if ((access = stat(pc_read.fpath, &st_cache)) == 0) {
    // get current time
    if (clock_gettime(CLOCK_REALTIME, &ts_current) == -1) {
      perror("clock_gettime");
    }
    // calculate difference between current time and st.st_mtim.tv_sec
    diff = ts_current.tv_sec - st_cache.st_mtim.tv_sec;
  }

  if (access == -1 ||
      diff > cache_timeout) {  // non-existent or stale cache entry
    // delete stale entry
    if (access == 0) {
      unlink(pc_read.fpath);
    }

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

    sb_send.sockfd = origin_sockfd;
    sb_send.data = build_request(&http_cmd, &http_hdrs, n_hdrs, &len_request);
    sb_send.len_data = len_request;

    // send to origin server
    if (pthread_create(&tid_forward_request, NULL, async_proxy_send, &sb_send) <
        0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);
      exit(EXIT_FAILURE);
    }

    // recv from origin server
    sb_recv.sockfd = origin_sockfd;
    // TODO: should set this differently than fine-grained timeout
    //       *not necessary to fulfill MVP*
    set_timeout(client_sockfd, RCVTIMEO_SEC, RCVTIMEO_USEC);

    if (pthread_create(&tid_recv, NULL, async_proxy_recv, &sb_recv) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);
      exit(EXIT_FAILURE);
    }

    free_recv_buf = 1;

    pthread_join(tid_recv, NULL);

    // free old sb_send.data
    free(sb_send.data);
    // don't need anymore
    close(origin_sockfd);

    // prefetch response
    if (pthread_create(&tid_prefetch_response, NULL, async_prefetch_response,
                       &sb_recv) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);
      exit(EXIT_FAILURE);
    }

    // allocate space for socket send buffer
    if ((sb_send.data = alloc_buf(sb_recv.len_data)) == NULL) {
      fprintf(stderr, "[FATAL] out of memory\n");
      free(sb_recv.data);

      exit(EXIT_FAILURE);
    }

    // copy received bytes to socket send buffer
    memcpy(sb_send.data, sb_recv.data, sb_recv.len_data);  // avoid double-free
    sb_send.len_data = sb_recv.len_data;

    // allocate space for cache write buffer
    if ((pc_write.data = alloc_buf(sb_recv.len_data)) == NULL) {
      fprintf(stderr, "[FATAL] out of memory\n");
      free(sb_send.data);
      free(sb_recv.data);

      exit(EXIT_FAILURE);
    }

    // copy received bytes to cache write buffer
    memcpy(pc_write.data, sb_recv.data, sb_recv.len_data);
    pc_write.len_data = sb_recv.len_data;
  } else {  // in cache, retrieve it
    if (pthread_create(&tid_read_cache, NULL, async_read_cache, &pc_read) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);
      exit(EXIT_FAILURE);
    }
    pthread_join(tid_read_cache, NULL);

    // allocate space for socket send buffer
    if ((sb_send.data = alloc_buf(pc_read.len_data)) == NULL) {
      fprintf(stderr, "[FATAL] out of memory\n");

      exit(EXIT_FAILURE);
    }

    // copy read bytes from cache to socket send buffer
    memcpy(sb_send.data, pc_read.data, pc_read.len_data);
    sb_send.len_data = pc_read.len_data;

    // allocate space for cache write buffer
    if ((pc_write.data = alloc_buf(pc_read.len_data)) == NULL) {
      fprintf(stderr, "[FATAL] out of memory\n");
      free(sb_send.data);

      exit(EXIT_FAILURE);
    }

    // copy read bytes from cache to cache write buffer (refreshes cache entry)
    memcpy(pc_write.data, pc_read.data, pc_read.len_data);
    pc_write.len_data = pc_read.len_data;

    free_recv_buf = 0;
  }

  // send response to client
  sb_send.sockfd = client_sockfd;
  if (pthread_create(&tid_forward_response, NULL, async_proxy_send, &sb_send) <
      0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  // cache response
  if (!*(http_cmd.uri.query[0].key)) {  // static content, cache it
    strncpy(pc_write.fpath, pc_read.fpath, HTTP_FNAME_MAX);

    if (pthread_create(&tid_cache_response, NULL, async_cache_response,
                       &pc_write) < 0) {
      fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
              __LINE__ - 1);
      exit(EXIT_FAILURE);
    }
  }

  pthread_join(tid_forward_request, NULL);
  pthread_join(tid_forward_response, NULL);
  pthread_join(tid_cache_response, NULL);
  pthread_join(tid_prefetch_response, NULL);

  free(http_hdrs);
  if (free_recv_buf == 1) {  // may not have recieved from origin if we went
                             // straight to cache, didn't allocate, no need to
                             // free
    free(sb_recv.data);
  }

  free(sb_send.data);
  free(pc_write.data);
  free(pc_read.data);

#ifdef DEBUG
  fprintf(stderr, "[%s:%d] socket %d: connection closed\n", __func__, chld_pid,
          client_sockfd);
#endif
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

        strncpy(http_query[i].key, key, HTTP_PARAM_KEY_MAX);
        buf_offset += key_len + 1;  // for '='

        strncpy(http_query[i].value, value, HTTP_PARAM_VALUE_MAX);
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
  int buf_offset, tmp_buf_offset;

  if ((tmp_buf_offset = parse_command(client_buf, nb_recv, http_cmd)) == -1) {
    return HTTP_BAD_REQUEST_CODE;
  }
  buf_offset = tmp_buf_offset;

  if (!validate_method(http_cmd->method)) {
    return HTTP_BAD_REQUEST_CODE;
  }

  // more data in headers, so validate command first (could return early)
  if ((tmp_buf_offset += parse_headers(
           client_buf + buf_offset, nb_recv - buf_offset, http_hdrs, n_hdrs)) ==
      -1) {
    return HTTP_BAD_REQUEST_CODE;
  }

  return 0;
}

/*
    typedef struct {
      HTTPHost host;
      HTTPQuery *query;
    } HTTPUri;
 */
ssize_t parse_uri(char *buf, size_t len_buf, HTTPUri *http_uri) {
  ssize_t skip;
  size_t scheme_end;

  scheme_end = 0;
  scheme_end +=
      read_until(buf, len_buf, ':', http_uri->host.scheme, HTTP_SCHEME_MAX);
  strncat(http_uri->host.scheme, buf + scheme_end - 1, sizeof("://") - 1);
  scheme_end += 2;

  skip = parse_host(buf + scheme_end, len_buf, &(http_uri->host));
  skip += parse_query(buf + skip, http_uri->query);

  return skip;
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
  chk_alloc_err(out_buf, "malloc", __func__, __LINE__ - 1);

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

void rebuild_uri(char *uri, HTTPCommand *http_cmd, int include_host) {
  size_t len_uri;

  len_uri = 0;

  if (include_host) {
    len_uri += snprintf(uri,
                        sizeof(http_cmd->uri.host.scheme) +
                            sizeof(http_cmd->uri.host.hostname) +
                            sizeof(http_cmd->uri.host.port) +
                            sizeof(http_cmd->uri.host.remote_uri),
                        "%s%s:%s%s", http_cmd->uri.host.scheme,
                        http_cmd->uri.host.hostname, http_cmd->uri.host.port,
                        http_cmd->uri.host.remote_uri) +
               1;
  } else {
    len_uri += snprintf(uri, sizeof(http_cmd->uri.host.remote_uri), "%s",
                        http_cmd->uri.host.remote_uri);
  }

  // query parameters
  for (size_t i = 0; *(http_cmd->uri.query[i].key) != '\0'; ++i) {
    if (i == 0) {
      len_uri += snprintf(uri + len_uri, sizeof(char) + 1, "%c", '?');
    } else {
      len_uri += snprintf(uri + len_uri, sizeof(char) + 1, "%c", '&');
    }

    len_uri += snprintf(uri + len_uri, HTTP_PARAM_KEY_MAX + 1,
                        "%s=", http_cmd->uri.query[i].key);
    len_uri += snprintf(uri + len_uri, HTTP_PARAM_VALUE_MAX, "%s",
                        http_cmd->uri.query[i].value);
  }
}

int send_err(int sockfd, size_t http_status_code) {
  const char *err_file;
  char *send_buf, *file_contents;
  char headers[HTTP_MAX_ERR_HEADER + 1];
  size_t nb_read, len_send_buf, len_headers;
  SocketBuffer sb_send;

  switch (http_status_code) {
    case HTTP_BAD_REQUEST_CODE:
      err_file = HTML_400;
      break;
    case HTTP_NOT_FOUND_CODE:
      err_file = HTML_404;
      break;
    default:
      fprintf(stderr, "[FATAL] this code should be unreachable\n");
      exit(EXIT_FAILURE);
  }

  if ((file_contents = read_file(err_file, &nb_read)) == NULL) {
    fprintf(stderr, "[ERROR] unable to read file %s\n", err_file);
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

  sb_send.sockfd = sockfd;
  sb_send.data = send_buf;
  sb_send.len_data = len_send_buf;

  if (pthread_create(&tid_send_err, NULL, async_proxy_send, &sb_send) < 0) {
    fprintf(stderr, "[ERROR] could not create thread: %s:%d\n", __func__,
            __LINE__ - 1);
    exit(EXIT_FAILURE);
  }

  pthread_join(tid_send_err, NULL);

  free(file_contents);
  free(sb_send.data);

  return 0;
}

size_t skip_scheme(char *buf) {
  size_t i;

  i = 0;
  while (i < HTTP_SCHEME_MAX && buf[i] != '/') {
    i++;
  }

  return i == HTTP_SCHEME_MAX - 1 ? 0 : i + 2;  // move past second '/'
}

size_t strnins(char *dst, const char *src, size_t n) {
  size_t src_len, dst_len;

  src_len = strlen(src) + 1;
  dst_len = strlen(dst) + 1;

  if (n > src_len) {
    n = src_len;
  }

  char tmp[dst_len + n + 1];
  strncpy(tmp, dst, dst_len);
  strncpy(dst, src, src_len);
  strncpy(dst + src_len - 1, tmp, dst_len);

  return n;
}

int validate_method(char *method) {
  unsigned long method_hash, valid_hash;

  valid_hash = hash_djb2("GET");
  method_hash = hash_djb2(method);

  return valid_hash == method_hash;
}

// === DEBUG FUNCTIONS ===
void print_command(HTTPCommand http_cmd) {
  fprintf(stderr, "\nHTTPCommand {\n");

  fprintf(stderr, "  Method: %s\n", http_cmd.method);
  fprintf(stderr, "  HTTPUri {\n");
  fprintf(stderr, "    HTTPHost {\n");
  fprintf(stderr, "      scheme: %s\n", http_cmd.uri.host.scheme);
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
