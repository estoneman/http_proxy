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

void handle_connection(int sockfd) {
  char *recv_buf;
  int parse_rc;
  ssize_t nb_recv;
  HTTPCommand http_cmd;
  HTTPHeader http_hdrs[HTTP_HEADERS_MAX];

  if ((recv_buf = proxy_recv(sockfd, &nb_recv)) == NULL) {
    exit(EXIT_FAILURE);  // child exit
  }

  fprintf(stderr, "[INFO] received %zd bytes\n", nb_recv);
  fflush(stderr);

  if ((parse_rc = parse_request(recv_buf, nb_recv, &http_cmd, http_hdrs)) ==
      HTTP_BAD_REQUEST) {
    // send 400.html
    fprintf(stderr, "[INFO] %d %s\n", parse_rc, http_status_msg(parse_rc));
  } else {
    // print_command(http_cmd);
  }

  free(recv_buf);
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

const char *http_status_msg(int http_status) {
  switch (http_status) {
    case HTTP_BAD_REQUEST:
      return "Bad Request";
    case HTTP_NOT_FOUND:
      return "Not Found";
    case HTTP_METHOD_NOT_ALLOWED:
      return "Method Not Allowed";
    case HTTP_VERSION_NOT_SUPPORTED:
      return "HTTP Version Not Supported";
    default:
      fprintf(stderr, "[FATAL] this code should be unreachable\n");
      exit(EXIT_FAILURE);
  }
}

/*
    typedef struct {
      char method[HTTP_METHOD_MAX];
      HTTPUri http_uri;
      char version[HTTP_VERSION_MAX];
    } HTTPCommand;
 */
ssize_t parse_command(char *line, size_t line_len, HTTPCommand *http_cmd) {
  ssize_t buf_offset, tmp_buf_offset;
  char uri[HTTP_URI_MAX];

  tmp_buf_offset = read_until(line, line_len, ' ', http_cmd->method,
                              sizeof(http_cmd->method));
  if (tmp_buf_offset == -1) return -1;
  buf_offset = tmp_buf_offset;

  tmp_buf_offset = read_until(line + buf_offset, line_len - buf_offset, ' ',
                              uri, sizeof(uri));
  if (tmp_buf_offset == -1) return -1;
  buf_offset += tmp_buf_offset;

  tmp_buf_offset = parse_uri(uri, sizeof(uri), &(http_cmd->http_uri));
  if (tmp_buf_offset == -1) return -1;
  // no need to add to `buf_offset`, did 4 lines above

  tmp_buf_offset = read_until(line + buf_offset, line_len - buf_offset, '\0',
                              http_cmd->version, sizeof(http_cmd->version));
  if (tmp_buf_offset == -1) return -1;
  buf_offset += tmp_buf_offset;

  return buf_offset;
}

/*
    typedef struct {
      char key[HTTP_HEADER_KEY_MAX];
      char value[HTTP_HEADER_VALUE_MAX];
    } HTTPHeader;
 */
ssize_t parse_headers(char *recv_buf, ssize_t nb_recv, HTTPHeader *http_hdrs) {
  (void)recv_buf;
  (void)nb_recv;
  (void)http_hdrs;

  return 0;
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
      char param_key[HTTP_PARAM_KEY_MAX];
      char param_value[HTTP_PARAM_VALUE_MAX];
    } HTTPQuery;
 */
ssize_t parse_query(char *buf, HTTPQuery *http_query) {
  char *param_sep = "&", *keyval_sep = "=";
  char *param_saveptr, *param_key, *param_value, *value;
  ssize_t buf_offset;
  size_t i;

  memset(http_query, 0, sizeof(http_query) * HTTP_QUERIES_MAX);
  param_key = strtok_r(buf, param_sep, &param_saveptr);
  buf_offset = 0;
  i = 0;

  while (param_key != NULL) {
    value = strtok_r(param_key, keyval_sep, &param_value);
    while (value != NULL) {
      value = strtok_r(NULL, keyval_sep, &param_value);
      if (value) {
        size_t param_key_len = strlen(param_key);
        size_t param_value_len = strlen(value);

        strncpy(http_query[i].param_key, param_key, strlen(param_key));
        buf_offset += param_key_len + 1;  // for '='

        strncpy(http_query[i].param_value, value, strlen(value));
        buf_offset += param_value_len;  // for '&'

        i++;
      }
    }
    param_key = strtok_r(NULL, param_sep, &param_saveptr);
  }

  return buf_offset > 0 ? buf_offset : -1;
}

ssize_t parse_request(char *recv_buf, ssize_t nb_recv, HTTPCommand *http_cmd,
                      HTTPHeader *http_hdrs) {
  int buf_offset, http_status;
  ssize_t skip;
  (void)http_status;
  (void)http_hdrs;

  char line[HTTP_MAXLINE_CMD];
  skip = http_readline(recv_buf, nb_recv, line);

  if ((buf_offset = parse_command(line, strlen(line), http_cmd)) == -1) {
    return HTTP_BAD_REQUEST;
  }

  (void)skip;
  // if ((http_status = validate_command(http_cmd)) > 0) {
  //   fprintf(stderr, "[ERROR] invalid command: %d %s\n", http_status,
  //           http_status_msg(http_status));

  //   return http_status;
  // }

  // more data in headers, so validate command first (could return early)
  // TODO: not sure if i need to return an offset from `parse_headers`
  // if ((buf_offset += parse_headers(recv_buf + buf_offset, nb_recv,
  // http_hdrs))
  //     == -1 ) {
  //   fprintf(stderr, "[ERROR] unable to parse headers\n");

  //   return HTTP_BAD_REQUEST;
  // }

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
      HTTPHost http_host;
      HTTPQuery *http_query;
    } HTTPUri;
 */
ssize_t parse_uri(char *buf, size_t len_buf, HTTPUri *http_uri) {
  ssize_t skip;

  buf += skip_scheme(buf);

  skip = parse_host(buf, len_buf, &(http_uri->http_host));
  skip += parse_query(buf + skip, http_uri->http_query);

  return skip;
}

void print_command(HTTPCommand http_cmd) {
  fprintf(stderr, "[INFO]\nHTTPCommand {\n");

  fprintf(stderr, "  Method: %s\n", http_cmd.method);
  fprintf(stderr, "  HTTPUri {\n");
  fprintf(stderr, "    HTTPHost {\n");
  fprintf(stderr, "      hostname: %s\n", http_cmd.http_uri.http_host.hostname);
  fprintf(stderr, "      port: %s\n", http_cmd.http_uri.http_host.port);
  fprintf(stderr, "      remote_uri: %s\n",
          http_cmd.http_uri.http_host.remote_uri);
  fprintf(stderr, "    }\n");
  fprintf(stderr, "    HTTPQuery {\n");

  for (size_t i = 0; *(http_cmd.http_uri.http_query[i].param_key) != '\0';
       ++i) {
    fprintf(stderr, "      key: %s\n",
            http_cmd.http_uri.http_query[i].param_key);
    fprintf(stderr, "      value: %s\n",
            http_cmd.http_uri.http_query[i].param_value);
  }

  fprintf(stderr, "    }\n");
  fprintf(stderr, "  }\n");
  fprintf(stderr, "  version: %s\n", http_cmd.version);
  fprintf(stderr, "}\n");

  fflush(stderr);
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
  while ((*nb_recv = recv(sockfd, recv_buf + total_nb_recv, RECV_CHUNK_SZ, 0)) >
         0) {
    total_nb_recv += (size_t)*nb_recv;
    // allocate more memory
    if (*nb_recv == RECV_CHUNK_SZ && total_nb_recv == bytes_alloced) {
      realloc_sz = total_nb_recv + (RECV_CHUNK_SZ * (int)pow(2, num_reallocs));
      if ((recv_buf = realloc_buf(recv_buf, realloc_sz)) == NULL) {
        free(recv_buf);  // avoid memory leak of previous buffer on `realloc` failure
        return NULL;
      }
      num_reallocs++;
      bytes_alloced = realloc_sz;
    }
  }

  if (total_nb_recv == 0) {
    // someone connected, but did not send us data
    free(recv_buf);
    return NULL;
  }

  *nb_recv = total_nb_recv;

  return recv_buf;
}

ssize_t read_until(char *haystack, size_t len_haystack, char end, char *sink,
                   size_t len_sink) {
  // move past space between ':' and header value
  while (isspace(*haystack)) {
    haystack += 1;
  }

  // up to the length of the input buffer, read as many characters are allowed
  // in `sink`
  size_t i;
  for (i = 0; i < len_haystack && i < len_sink && haystack[i] != end; ++i) {
    sink[i] = haystack[i];
  }

  // if nothing found, bad request
  if (haystack[i] != end) {
    return -1;
  }

  sink[i] = '\0';

  return (ssize_t)i + 1;  // move pointer to next field of http status line
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

size_t skip_scheme(char *buf) {
  size_t i;

  i = 0;
  while (buf[i] != '/') {
    i++;
  }

  return i + 2;
}
