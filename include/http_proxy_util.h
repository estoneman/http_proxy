/* http_proxy_util.h */

#ifndef HTTP_PROXY_UTIL_H_
#define HTTP_PROXY_UTIL_H_

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CACHE_BASE "./cache/"
#define CRLF "\r\n"
#define HASH_LEN 16
#define HTML_400 "./err/400.html"
#define HTML_403 "./err/403.html"
#define HTML_404 "./err/404.html"

#define HTTP_FNAME_MAX sizeof(CACHE_BASE) + HASH_LEN + 1
#define HTTP_HEADER_KEY_MAX 64
#define HTTP_HEADER_VALUE_MAX 1024
#define HTTP_HEADERS_MAX 32
#define HTTP_HOSTNAME_MAX 256
#define HTTP_MAX_ERR_HEADER 1024
#define HTTP_MAXLINE_CMD (HTTP_METHOD_MAX + HTTP_URI_MAX + HTTP_VERSION_MAX)
#define HTTP_MAXLINE_HDR HTTP_HEADER_KEY_MAX + HTTP_HEADER_VALUE_MAX
#define HTTP_METHOD_MAX 8
#define HTTP_PARAM_KEY_MAX 256
#define HTTP_PARAM_VALUE_MAX 256
#define HTTP_PORT_MAX_DIGITS 5
#define HTTP_QUERIES_MAX 32
#define HTTP_REMOTE_MAX 1024
#define HTTP_SCHEME_MAX 16
#define HTTP_SCHEME "http://"
#define HTTP_URI_MAX \
  (HTTP_HOSTNAME_MAX + HTTP_PORT_MAX_DIGITS + HTTP_REMOTE_MAX)
#define HTTP_VERSION_MAX 16

#define HTTP_BAD_REQUEST_CODE 400
#define HTTP_FORBIDDEN_CODE 403
#define HTTP_NOT_FOUND_CODE 404
#define HTTP_METHOD_NOT_ALLOWED_CODE 405
#define HTTP_VERSION_NOT_SUPPORTED_CODE 505

#define MAX_URLS 128
#define MAX_URL_SZ 4096

typedef struct {
  char scheme[HTTP_SCHEME_MAX];
  char hostname[HTTP_HOSTNAME_MAX];
  char port[HTTP_PORT_MAX_DIGITS];
  char remote_uri[HTTP_REMOTE_MAX];
} HTTPHost;

typedef struct {
  char key[HTTP_PARAM_KEY_MAX];
  char value[HTTP_PARAM_VALUE_MAX];
} HTTPQuery;

typedef struct {
  HTTPHost host;
  HTTPQuery query[HTTP_QUERIES_MAX];
} HTTPUri;

typedef struct {
  char method[HTTP_METHOD_MAX];
  HTTPUri uri;
  char version[HTTP_VERSION_MAX];
} HTTPCommand;

typedef struct {
  char key[HTTP_HEADER_KEY_MAX];
  char value[HTTP_HEADER_VALUE_MAX];
} HTTPHeader;

char *alloc_buf(size_t);
char *build_request(HTTPCommand *, HTTPHeader **, size_t, size_t *);
int chk_alloc_err(void *, const char *, const char *, int);
ssize_t find_crlf(char *, size_t);
char **get_urls(char *, size_t, size_t *);
void handle_connection(int, int);
unsigned long hash_djb2(const char *);
ssize_t http_readline(char *, size_t, char *);
const char *http_status_msg(int);
ssize_t parse_command(char *, size_t, HTTPCommand *);
ssize_t parse_headers(char *, size_t, HTTPHeader *, size_t *);
ssize_t parse_host(char *, size_t, HTTPHost *);
ssize_t parse_query(char *, HTTPQuery *);
ssize_t parse_request(char *, ssize_t, HTTPCommand *, HTTPHeader *, size_t *);
ssize_t parse_uri(char *, size_t, HTTPUri *);
char *read_file(const char *, size_t *);
ssize_t read_until(char *, size_t, char, char *, size_t);
char *realloc_buf(char *, size_t size);
void rebuild_uri(char *, HTTPCommand *, int);
int send_err(int, size_t);
size_t skip_scheme(char *);
size_t strnins(char *dst, const char *src, size_t n);
int validate_method(char *);

// debug
void print_command(HTTPCommand);
void print_header(HTTPHeader);
void print_headers(HTTPHeader *, size_t);
void print_request(HTTPHeader *, size_t, HTTPCommand);
#endif  // HTTP_PROXY_UTIL_H_
