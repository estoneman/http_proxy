#ifndef HTTP_PROXY_UTIL_H_
#define HTTP_PROXY_UTIL_H_

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#define HTML_400 "./err/400.html"
#define HTML_404 "./err/404.html"

#define HTTP_HEADER_KEY_MAX 64
#define HTTP_HEADER_VALUE_MAX 1024
#define HTTP_HEADERS_MAX 32
#define HTTP_HOSTNAME_MAX 256
#define HTTP_MAX_ERR_HEADER 1024
#define HTTP_MAXLINE_CMD (HTTP_METHOD_MAX + HTTP_URI_MAX + HTTP_VERSION_MAX)
#define HTTP_METHOD_MAX 8
#define HTTP_PARAM_KEY_MAX 256
#define HTTP_PARAM_VALUE_MAX 256
#define HTTP_PORT_MAX_DIGITS 5
#define HTTP_QUERIES_MAX 32
#define HTTP_REMOTE_MAX 1024
#define HTTP_URI_MAX \
  (HTTP_HOSTNAME_MAX + HTTP_PORT_MAX_DIGITS + HTTP_REMOTE_MAX)
#define HTTP_VERSION_MAX 16

#define HTTP_BAD_REQUEST 400
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_VERSION_NOT_SUPPORTED 505

typedef struct {
  char hostname[HTTP_HOSTNAME_MAX];
  char port[HTTP_PORT_MAX_DIGITS];
  char remote_uri[HTTP_REMOTE_MAX];
} HTTPHost;

typedef struct {
  char param_key[HTTP_PARAM_KEY_MAX];
  char param_value[HTTP_PARAM_VALUE_MAX];
} HTTPQuery;

typedef struct {
  HTTPHost http_host;
  HTTPQuery http_query[HTTP_QUERIES_MAX];
} HTTPUri;

typedef struct {
  char method[HTTP_METHOD_MAX];
  HTTPUri http_uri;
  char version[HTTP_VERSION_MAX];
} HTTPCommand;

typedef struct {
  char key[HTTP_HEADER_KEY_MAX];
  char value[HTTP_HEADER_VALUE_MAX];
} HTTPHeader;

char *alloc_buf(size_t);
int chk_alloc_err(void *, const char *, const char *, int);
ssize_t find_crlf(char *, size_t);
void handle_connection(int);
const char *http_status_msg(int);
ssize_t http_readline(char *, size_t, char *);
ssize_t parse_command(char *, size_t, HTTPCommand *);
ssize_t parse_headers(char *, ssize_t, HTTPHeader *);
ssize_t parse_host(char *, size_t, HTTPHost *);
ssize_t parse_query(char *, HTTPQuery *);
ssize_t parse_request(char *, ssize_t, HTTPCommand *, HTTPHeader *);
ssize_t parse_uri(char *, size_t, HTTPUri *);
char *proxy_recv(int, ssize_t *);
ssize_t proxy_send(int, char *, size_t);
char *read_file(const char *, size_t *);
ssize_t read_until(char *, size_t, char, char *, size_t);
char *realloc_buf(char *, size_t size);
int send_err(int, const char *, size_t);
size_t skip_scheme(char *);

// debug
void print_command(HTTPCommand);
#endif  // HTTP_PROXY_UTIL_H_
