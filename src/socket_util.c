#include "../include/socket_util.h"

int connection_sockfd(const char *hostname, const char *port) {
  struct addrinfo hints, *srv_entries, *srv_entry;
  int sockfd, addrinfo_status;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

#ifdef DEBUG
  fprintf(stderr, "[%s] connecting to %s:%s\n", __func__, hostname, port);
#endif
  if ((addrinfo_status = getaddrinfo(hostname, port, &hints, &srv_entries)) <
      0) {
    fprintf(stderr, "[ERROR] getaddrinfo: %s\n", gai_strerror(addrinfo_status));

    return HTTP_NOT_FOUND_CODE;
  }

  // look up ip in blocklist
  for (srv_entry = srv_entries; srv_entry != NULL;
       srv_entry = srv_entry->ai_next) {
  }

  // loop through results of call to getaddrinfo
  for (srv_entry = srv_entries; srv_entry != NULL;
       srv_entry = srv_entry->ai_next) {
    // create socket through which server communication will be facililated
    if ((sockfd = socket(srv_entry->ai_family, srv_entry->ai_socktype,
                         srv_entry->ai_protocol)) < 0) {
      perror("socket");
      continue;
    }

    if (is_blocked(hostname, srv_entry) & 1) {
      return HTTP_FORBIDDEN_CODE;
    }

    /*
     * EINPROGRESS
         The socket is nonblocking and the connection cannot be completed
       immediately. (UNIX domain sockets failed with EAGAIN instead.) It is
       possible to select(2) or poll(2) for completion by selecting the socket
       for writing. After select(2) indicates writability, use getsockopt(2) to
       read the SO_ERROR option at level SOL_SOCKET to determine whether
       connect() completed successfully (SO_ERROR is zero) or unsuccessfully
       (SO_ERROR  is one of the usual error codes listed here, explaining the
       reason for the failure).
     */
    if (connect(sockfd, srv_entry->ai_addr, srv_entry->ai_addrlen) < 0) {
      close(sockfd);
      continue;
    }

    break;  // successfully created socket and connected to remote service
  }

  if (srv_entry == NULL) {
    freeaddrinfo(srv_entries);
    return HTTP_NOT_FOUND_CODE;
  }

  freeaddrinfo(srv_entries);

  return sockfd;
}

int listen_sockfd(const char *port) {
  struct addrinfo hints, *srv_entries, *srv_entry;
  int sockfd, addrinfo_status, enable;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((addrinfo_status = getaddrinfo(NULL, port, &hints, &srv_entries)) < 0) {
    fprintf(stderr, "[ERROR] getaddrinfo: %s\n", gai_strerror(addrinfo_status));
    return -1;
  }

  // loop through results of call to getaddrinfo
  for (srv_entry = srv_entries; srv_entry != NULL;
       srv_entry = srv_entry->ai_next) {
    // create socket through which server communication will be facililated
    if ((sockfd = socket(srv_entry->ai_family, srv_entry->ai_socktype,
                         srv_entry->ai_protocol)) < 0) {
      perror("socket");
      continue;
    }

    // convenience socket option for rapid reuse of sockets
    enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
        0) {
      perror("setsockopt");
      return -1;
    }

    // bind socket to current candidate
    if (bind(sockfd, srv_entry->ai_addr, srv_entry->ai_addrlen) < 0) {
      perror("bind");
      continue;
    }

    break;  // successfully created socket and binded to address
  }

  if (srv_entry == NULL) {
    fprintf(stderr, "[ERROR] could not bind to any address\n");
    freeaddrinfo(srv_entries);

    return -1;
  }

  freeaddrinfo(srv_entries);

  return sockfd;
}

void *get_inetaddr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void get_ipstr(char *ipstr, struct sockaddr *addr) {
  inet_ntop(addr->sa_family, get_inetaddr(addr), ipstr, INET6_ADDRSTRLEN);
}

int is_blocked(const char *hostname, struct addrinfo *srv_entry) {
  void *addr;
  char ipstr[INET6_ADDRSTRLEN];
  char *blocklist;
  size_t nb_read;
  char *delim = "\n";
  char *blocked_host;

  if (srv_entry->ai_family == AF_INET) {
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)srv_entry->ai_addr;
    addr = &(ipv4->sin_addr);
  } else {
    struct sockaddr_in6 *ipv4 = (struct sockaddr_in6 *)srv_entry->ai_addr;
    addr = &(ipv4->sin6_addr);
  }

  inet_ntop(srv_entry->ai_family, addr, ipstr, sizeof(ipstr));
  blocklist = read_file("./blocklist", &nb_read);
  blocked_host = strtok(blocklist, delim);

  unsigned long blocked_hash, ip_hash, hostname_hash;
  while (blocked_host != NULL) {
    blocked_hash = strtoul(blocked_host, NULL, 16);
    ip_hash = hash_djb2(ipstr);
    hostname_hash = hash_djb2(hostname);
#ifdef DEBUG
    fprintf(stderr, "[%s] comparing %lx and %s\n", __func__, ip_hash,
            blocked_host);
    fflush(stderr);
#endif
    if (blocked_hash == ip_hash) {
      free(blocklist);

      return 1;
    }
#ifdef DEBUG
    fprintf(stderr, "[%s] comparing %lx and %s\n", __func__, hostname_hash,
            blocked_host);
    fflush(stderr);
#endif
    if (blocked_hash == hostname_hash) {
      free(blocklist);

      return 1;
    }

    blocked_host = strtok(NULL, delim);
  }

  free(blocklist);

  return 0;
}
int is_valid_port(const char *arg) {
  int port = atoi(arg);
  return (port >= 1024 && port <= 65535);
}

char *proxy_recv(int sockfd, ssize_t *nb_recv) {
  char *recv_buf;
  size_t total_nb_recv, num_reallocs, bytes_alloced, realloc_sz;

  if ((recv_buf = alloc_buf(RECV_CHUNK_SZ)) == NULL) {
    fprintf(stderr, "failed to allocate receive buffer (%s:%d)", __func__,
            __LINE__ - 1);
    return NULL;
  }

  set_timeout(sockfd, RCVTIMEO_SEC, RCVTIMEO_USEC);

  bytes_alloced = RECV_CHUNK_SZ;

  total_nb_recv = realloc_sz = num_reallocs = 0;
  while ((*nb_recv = recv(sockfd, recv_buf + total_nb_recv, RECV_CHUNK_SZ, 0)) >
         0) {
    total_nb_recv += *nb_recv;

    if (total_nb_recv + RECV_CHUNK_SZ >= bytes_alloced) {
      realloc_sz = bytes_alloced * 2;
      if ((recv_buf = realloc_buf(recv_buf, realloc_sz)) == NULL) {
        fprintf(stderr, "[FATAL] out of memory: attempted realloc size = %zu\n",
                realloc_sz);
        free(recv_buf);  // free old buffer

        exit(EXIT_FAILURE);
      }
    }

    bytes_alloced = realloc_sz;
    num_reallocs++;
  }

  *nb_recv = total_nb_recv;

  if (total_nb_recv == 0) {  // timeout
    perror("recv");
    free(recv_buf);

    return NULL;
  }

  return recv_buf;
}

ssize_t proxy_send(int sockfd, char *send_buf, size_t len_send_buf) {
  ssize_t nb_sent;

  if ((nb_sent = send(sockfd, send_buf, len_send_buf, 0)) < 0) {
    perror("send");
    return -1;
  }

  return nb_sent;
}

void set_timeout(int sockfd, long tv_sec, long tv_usec) {
  struct timeval rcvtimeo;

  rcvtimeo.tv_sec = tv_sec;
  rcvtimeo.tv_usec = tv_usec;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo)) <
      0) {
    perror("setsockopt");
    close(sockfd);
    exit(EXIT_FAILURE);
  }
}
