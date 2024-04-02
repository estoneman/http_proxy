/* http_proxy.c */

#include <signal.h>
#include <sys/wait.h>

#include "../include/http_proxy_util.h"
#include "../include/socket_util.h"

#define PORT_LEN 6

void usage(const char *program) {
  fprintf(stderr, "usage: %s <port (1024|65535)\n", program);
}

void sigchld_handler(int s __attribute__((unused))) {
  int saved_errno = errno;

  while (waitpid(-1, NULL, WNOHANG) > 0) {
  }  // reap dead child processes

  errno = saved_errno;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "[ERROR] not enough arguments supplied\n");
    usage(argv[0]);
    exit(EXIT_FAILURE);
  } else if (!is_valid_port(argv[1])) {
    fprintf(stderr, "[ERROR] invalid port specified\n");
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in cliaddr;
  socklen_t cliaddr_len;
  int listenfd, connfd;
  char port[PORT_LEN], ipstr[INET6_ADDRSTRLEN];
  struct sigaction sa;
  pid_t pid;

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

  fprintf(stderr, "[INFO] listening on 0.0.0.0:%s\n", port);

  cliaddr_len = sizeof(cliaddr);

  while (1) {
    if ((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len)) <
        0) {
      perror("accept");
      continue;
    }

    get_ipstr(ipstr, (struct sockaddr *)&cliaddr);
    fprintf(stderr, "[INFO] socket %d: new connection (%s:%d)\n", connfd, ipstr,
            ntohs(cliaddr.sin_port));

    if ((pid = fork()) < 0) {
      fprintf(stderr, "[ERROR] could not create child process: %s\n",
              strerror(errno));
      close(connfd);
      continue;
    }

    if (pid == 0) {  // child process
      close(listenfd);
      handle_connection(connfd);

      exit(EXIT_SUCCESS);
    } else {  // parent process
      close(connfd);
    }
  }

  return EXIT_SUCCESS;
}
