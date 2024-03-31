#include "../include/socket_util.h"

// create `connection_sock`
int connection_sock(const char *hostname, const char *port) {
  struct addrinfo hints, *srv_entries, *srv_entry;
  int sockfd, addrinfo_status;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((addrinfo_status = getaddrinfo(hostname, port, &hints, &srv_entries)) <
      0) {
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

    if (connect(sockfd, srv_entry->ai_addr, srv_entry->ai_addrlen) < 0) {
      close(sockfd);
      perror("connect");
      continue;
    }

    break;  // successfully created socket and connected to remote service
  }

  if (srv_entry == NULL) {
    freeaddrinfo(srv_entries);

    return -1;
  }

  freeaddrinfo(srv_entries);

  return sockfd;
}

int listen_sock(const char *port) {
  struct addrinfo hints, *srv_entries, *srv_entry;
  int sockfd, addrinfo_status;

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
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
        0) {
      perror("setsockopt");
      return -1;
    }

    // bind socket to network address(es)
    if (bind(sockfd, srv_entry->ai_addr, srv_entry->ai_addrlen) < 0) {
      perror("bind");
      continue;
    }

    break;  // successfully created socket and binded to address
  }

  if (srv_entry == NULL) {
    fprintf(stderr, "[ERROR] could not bind to any address\n");

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

int is_valid_port(const char *arg) {
  int port = atoi(arg);
  return (port >= 1024 && port <= 65535);
}

void set_timeout(int sockfd) {
  struct timeval rcvtimeo;

  rcvtimeo.tv_sec = 0;
  rcvtimeo.tv_usec = RCVTIMEO_USEC;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo)) <
      0) {
    perror("setsockopt");
    close(sockfd);
    exit(EXIT_FAILURE);
  }
}
