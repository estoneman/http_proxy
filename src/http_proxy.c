/* http_proxy.c */

#include <signal.h>
#include <sys/wait.h>

#include "../include/http_proxy_util.h"
#include "../include/socket_util.h"

#define BASE_10 10
#define PORT_LEN 6

void usage(const char *program) {
  fprintf(stderr,
          "usage: %s <port (1024|65535)> <cache timeout (default: 60)>\n",
          program);
}

void sigchld_handler(int s __attribute__((unused))) {
  int saved_errno = errno;

  while (waitpid(-1, NULL, WNOHANG) > 0) {
  }  // reap dead child processes

  errno = saved_errno;
}

int main(int argc, char *argv[]) {
  struct sockaddr_in cliaddr;
  socklen_t cliaddr_len;
  int listenfd, connfd;
  char port[PORT_LEN], ipstr[INET6_ADDRSTRLEN];
  char *invalid_digits;
  struct sigaction sa;
  pid_t pid;
  long cache_timeout;

  cache_timeout = 60;
  if (argc < 2) {
    fprintf(stderr, "[ERROR] not enough arguments supplied\n");
    usage(argv[0]);

    exit(EXIT_FAILURE);
  } else if (argc > 2) {
    if ((cache_timeout = strtol(argv[2], &invalid_digits, BASE_10)) == 0) {
      if (invalid_digits) {
        fprintf(stderr, "[ERROR] invalid timeout specified\n");
        usage(argv[0]);

        exit(EXIT_FAILURE);
      }
    }
  }

  if (!is_valid_port(argv[1])) {
    fprintf(stderr, "[ERROR] invalid port specified\n");
    usage(argv[0]);

    exit(EXIT_FAILURE);
  }

  strcpy(port, argv[1]);
  if ((listenfd = listen_sockfd(port)) == -1) {
    exit(EXIT_FAILURE);
  }

  if (listen(listenfd, SOMAXCONN) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }

  fprintf(stderr, "[%s] proxy listening on 0.0.0.0:%s, timeout = %ld\n",
          __func__, port, cache_timeout);

  cliaddr_len = sizeof(cliaddr);

  while (1) {
    if ((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len)) <
        0) {
      perror("accept");
      continue;
    }

    get_ipstr(ipstr, (struct sockaddr *)&cliaddr);
    fprintf(stderr, "[%s] socket %d: new connection (%s:%d)\n", __func__,
            connfd, ipstr, ntohs(cliaddr.sin_port));

    if ((pid = fork()) < 0) {
      fprintf(stderr, "[ERROR] could not create child process: %s\n",
              strerror(errno));
      close(connfd);
      continue;
    }

    if (pid == 0) {  // child process
      close(listenfd);
      handle_connection(connfd, cache_timeout);

      exit(EXIT_SUCCESS);
    } else {  // parent process
      close(connfd);
    }
  }

  return EXIT_SUCCESS;
}
