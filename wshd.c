#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/param.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "barrier.h"
#include "msg.h"
#include "mount.h"
#include "pty.h"
#include "pwd.h"
#include "un.h"
#include "util.h"

typedef struct wshd_s wshd_t;
int back_ground = 0;

struct wshd_s {
  /* Path to directory where server socket is placed */
  char run_path[256];

  /* Process title */
  char title[32];

  /* File descriptor of listening socket */
  int fd;

  /* Map pids to exit status fds */
  struct {
    pid_t pid;
    int fd;
  } *pid_to_fd;
  size_t pid_to_fd_len;
};

int wshd__usage(wshd_t *w, int argc, char **argv) {
  fprintf(stderr, "Usage: %s OPTION...\n", argv[0]);
  fprintf(stderr, "\n");

  fprintf(stderr, "  --run PATH   "
    "Directory where server socket is placed"
    "\n");

  fprintf(stderr, "  --title NAME "
    "Process title"
    "\n");

  return 0;
}

int wshd__getopt(wshd_t *w, int argc, char **argv) {
  int i = 1;
  int j = argc - i;
  int rv;

  while (i < argc) {
    if (j >= 2) {
      if (strcmp("--run", argv[i]) == 0) {
        rv = snprintf(w->run_path, sizeof(w->run_path), "%s", argv[i+1]);
        if (rv >= sizeof(w->run_path)) {
          goto toolong;
        }
      } else if (strcmp("--title", argv[i]) == 0) {
        rv = snprintf(w->title, sizeof(w->title), "%s", argv[i+1]);
        if (rv >= sizeof(w->title)) {
          goto toolong;
        }
      } else if (strcmp("-d", argv[i]) == 0) {
        back_ground = 1;
      } else {
        goto invalid;
      }

      i += 2;
      j -= 2;
    } else if (j == 1) {
      if (strcmp("-h", argv[i]) == 0 ||
          strcmp("--help", argv[i]) == 0)
      {
        wshd__usage(w, argc, argv);
        return -1;
      } else {
        goto invalid;
      }
    } else {
      assert(NULL);
    }
  }

  return 0;

toolong:
  fprintf(stderr, "%s: argument too long -- %s\n", argv[0], argv[i]);
  fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
  return -1;

invalid:
  fprintf(stderr, "%s: invalid option -- %s\n", argv[0], argv[i]);
  fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
  return -1;
}

void assert_directory(const char *path) {
  int rv;
  struct stat st;

  rv = stat(path, &st);
  if (rv == -1) {
    fprintf(stderr, "stat(\"%s\"): %s\n", path, strerror(errno));
    exit(1);
  }

  if (!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "stat(\"%s\"): %s\n", path, "No such directory");
    exit(1);
  }
}

void child_pid_to_fd_add(wshd_t *w, pid_t pid, int fd) {
  int len = w->pid_to_fd_len;

  /* Store a copy */
  fd = dup(fd);
  if (fd == -1) {
    perror("dup");
    abort();
  }

  w->pid_to_fd = realloc(w->pid_to_fd, (len + 1) * sizeof(w->pid_to_fd[0]));
  assert(w->pid_to_fd != NULL);

  w->pid_to_fd[len].pid = pid;
  w->pid_to_fd[len].fd = fd;
  w->pid_to_fd_len++;
}

int child_pid_to_fd_remove(wshd_t *w, pid_t pid) {
  int i;
  int len = w->pid_to_fd_len;
  int fd = -1;

  for (i = 0; i < len; i++) {
    if (w->pid_to_fd[i].pid == pid) {
      fd = w->pid_to_fd[i].fd;

      /* Move tail if there is one */
      if ((i + 1) < len) {
        memmove(&w->pid_to_fd[i], &w->pid_to_fd[i+1], (len - i - 1) * sizeof(w->pid_to_fd[0]));
      }

      w->pid_to_fd = realloc(w->pid_to_fd, (w->pid_to_fd_len - 1) * sizeof(w->pid_to_fd[0]));
      w->pid_to_fd_len--;

      if (w->pid_to_fd_len) {
        assert(w->pid_to_fd != NULL);
      } else {
        assert(w->pid_to_fd == NULL);
      }

      break;
    }
  }

  return fd;
}

char **env__add(char **envp, const char *key, const char *value) {
  size_t envplen = 0;
  char *buf;
  size_t buflen;
  int rv;

  if (envp == NULL) {
    /* Trailing NULL */
    envplen = 1;
  } else {
    while(envp[envplen++] != NULL);
  }

  envp = realloc(envp, sizeof(envp[0]) * (envplen + 1));
  assert(envp != NULL);

  buflen = strlen(key) + 1 + strlen(value) + 1;
  buf = malloc(buflen);
  assert(buf != NULL);

  rv = snprintf(buf, buflen, "%s=%s", key, value);
  assert(rv == buflen - 1);

  envp[envplen - 1] = buf;
  envp[envplen] = NULL;

  return envp;
}

char **child_setup_environment(struct passwd *pw) {
  int rv;
  char **envp = NULL;

  rv = chdir(pw->pw_dir);
  if (rv == -1) {
    perror("chdir");
    return NULL;
  }

  envp = env__add(envp, "HOME", pw->pw_dir);
  envp = env__add(envp, "USER", pw->pw_name);
  envp = env__add(envp, "TERM", "xterm");

  if (pw->pw_uid == 0) {
    envp = env__add(envp, "PATH", "/sbin:/bin:/usr/sbin:/usr/bin");
  } else {
    envp = env__add(envp, "PATH", "/bin:/usr/bin");
  }

  return envp;
}

int child_fork(msg_request_t *req, int in, int out, int err) {
  int rv;

  rv = fork();
  if (rv == -1) {
    perror("fork");
    exit(1);
  }

  if (rv == 0) {
    const char *user;
    struct passwd *pw;
    char *default_argv[] = { "/bin/bash", NULL };
    char *default_envp[] = { NULL };
    char **argv = default_argv;
    char **envp = default_envp;

    rv = dup2(in, STDIN_FILENO);
    assert(rv != -1);

    rv = dup2(out, STDOUT_FILENO);
    assert(rv != -1);

    rv = dup2(err, STDERR_FILENO);
    assert(rv != -1);

    rv = setsid();
    assert(rv != -1);

    user = req->user.name;
    if (!strlen(user)) {
      user = "root";
    }

    pw = getpwnam(user);
    if (pw == NULL) {
      perror("getpwnam");
      goto error;
    }

    if (strlen(pw->pw_shell)) {
      default_argv[0] = strdup(pw->pw_shell);
    }

    /* Set controlling terminal if needed */
    if (isatty(in)) {
      rv = ioctl(STDIN_FILENO, TIOCSCTTY, 1);
      assert(rv != -1);
    }

    /* Use argv from request if needed */
    if (req->arg.count) {
      argv = (char **)msg_array_export(&req->arg);
      assert(argv != NULL);
    }

    /*
    rv = msg_rlimit_export(&req->rlim);
    if (rv == -1) {
      perror("msg_rlimit_export");
      goto error;
    }
    */

    rv = msg_user_export(&req->user, pw);
    if (rv == -1) {
      perror("msg_user_export");
      goto error;
    }
    
    envp = child_setup_environment(pw);
    assert(envp != NULL);

    execvpe(argv[0], argv, envp);
    //execvp(argv[0], argv);
    perror("execvpe");

error:
    exit(255);
  }

  return rv;
}

int child_handle_interactive(int fd, wshd_t *w, msg_request_t *req) {
  int i, j;
  int p[2][2];
  int p_[2];
  int rv;
  msg_response_t res;

  msg_response_init(&res);

  /* Initialize so that the error handler can do its job */
  for (i = 0; i < 2; i++) {
    p[i][0] = -1;
    p[i][1] = -1;
    p_[i] = -1;
  }

  rv = pipe(p[1]);
  if (rv == -1) {
    perror("pipe");
    abort();
  }

  fcntl_mix_cloexec(p[1][0]);
  fcntl_mix_cloexec(p[1][1]);

  rv = openpty(&p[0][0], &p[0][1], NULL);
  if (rv < 0) {
    perror("openpty");
    abort();
  }

  fcntl_mix_cloexec(p[0][0]);
  fcntl_mix_cloexec(p[0][1]);

  /* Descriptors to send to client */
  p_[0] = p[0][0];
  p_[1] = p[1][0];

  rv = un_send_fds(fd, (char *)&res, sizeof(res), p_, 2);
  if (rv == -1) {
    goto err;
  }

  rv = child_fork(req, p[0][1], p[0][1], p[0][1]);
  assert(rv > 0);

  child_pid_to_fd_add(w, rv, p[1][1]);

err:
  for (i = 0; i < 2; i++) {
    for (j = 0; j < 2; j++) {
      if (p[i][j] > -1) {
        close(p[i][j]);
        p[i][j] = -1;
      }
    }
  }

  if (fd > -1) {
    close(fd);
    fd = -1;
  }

  return 0;
}

int child_handle_noninteractive(int fd, wshd_t *w, msg_request_t *req) {
  int i, j;
  int p[4][2];
  int p_[4];
  int rv;
  msg_response_t res;

  msg_response_init(&res);

  /* Initialize so that the error handler can do its job */
  for (i = 0; i < 4; i++) {
    p[i][0] = -1;
    p[i][1] = -1;
    p_[i] = -1;
  }

  for (i = 0; i < 4; i++) {
    rv = pipe(p[i]);
    if (rv == -1) {
      perror("pipe");
      abort();
    }

    fcntl_mix_cloexec(p[i][0]);
    fcntl_mix_cloexec(p[i][1]);
  }

  /* Descriptors to send to client */
  p_[0] = p[0][1];
  p_[1] = p[1][0];
  p_[2] = p[2][0];
  p_[3] = p[3][0];

  rv = un_send_fds(fd, (char *)&res, sizeof(res), p_, 4);
  if (rv == -1) {
    goto err;
  }

  rv = child_fork(req, p[0][0], p[1][1], p[2][1]);
  assert(rv > 0);

  child_pid_to_fd_add(w, rv, p[3][1]);

err:
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 2; j++) {
      if (p[i][j] > -1) {
        close(p[i][j]);
        p[i][j] = -1;
      }
    }
  }

  if (fd > -1) {
    close(fd);
    fd = -1;
  }

  return 0;
}

int child_accept(wshd_t *w) {
  int rv, fd;
  char buf[MSG_MAX_SIZE];
  size_t buflen = sizeof(buf);
  msg_request_t req;

  rv = accept(w->fd, NULL, NULL);
  if (rv == -1) {
    perror("accept");
    abort();
  }

  fd = rv;

  fcntl_mix_cloexec(fd);

  rv = un_recv_fds(fd, buf, buflen, NULL, 0);
  if (rv < 0) {
    perror("recvmsg");
    exit(255);
  }

  if (rv == 0) {
    close(fd);
    return 0;
  }

  assert(rv == sizeof(req));
  memcpy(&req, buf, sizeof(req));

  if (req.tty) {
    return child_handle_interactive(fd, w, &req);
  } else {
    return child_handle_noninteractive(fd, w, &req);
  }
}

void child_handle_sigchld(wshd_t *w) {
  pid_t pid;
  int status, exitstatus;
  int fd;

  while (1) {
    do {
      pid = waitpid(-1, &status, WNOHANG);
    } while (pid == -1 && errno == EINTR);

    /* Break when there are no more children */
    if (pid <= 0) {
      break;
    }

    /* Processes can be reparented, so a pid may not map to an fd */
    fd = child_pid_to_fd_remove(w, pid);
    if (fd == -1) {
      continue;
    }

    if (WIFEXITED(status)) {
      exitstatus = WEXITSTATUS(status);

      /* Send exit status to client */
      write(fd, &exitstatus, sizeof(exitstatus));
    } else {
      assert(WIFSIGNALED(status));

      /* No exit status */
    }

    close(fd);
  }
}

// 如果子进程退出，在此fd上触发事件
int child_signalfd(void) {
  sigset_t mask;
  int rv;
  int fd;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  rv = sigprocmask(SIG_BLOCK, &mask, NULL);
  if (rv == -1) {
    perror("sigprocmask");
    abort();
  }

  fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (fd == -1) {
    perror("signalfd");
    abort();
  }

  return fd;
}

int child_loop(wshd_t *w) {
  int sfd;
  int rv;

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  sfd = child_signalfd();

  for (;;) {
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(w->fd, &fds);
    FD_SET(sfd, &fds);

    do {
      rv = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
      perror("select");
      abort();
    }

    // unix socket上发生事件，有请求来
    if (FD_ISSET(w->fd, &fds)) {
      child_accept(w);
    }

    // signal fd上发生事件，有子进程退出
    if (FD_ISSET(sfd, &fds)) {
      struct signalfd_siginfo fdsi;

      rv = read(sfd, &fdsi, sizeof(fdsi));
      assert(rv == sizeof(fdsi));

      /* Ignore siginfo and loop waitpid to catch all children */
      child_handle_sigchld(w);
    }
  }

  return 1;
}

int parent_run(wshd_t *w) {
  char path[MAXPATHLEN];
  int rv;
  pid_t pid;

  memset(path, 0, sizeof(path));

  strcpy(path + strlen(path), w->run_path);
  strcpy(path + strlen(path), "/");
  strcpy(path + strlen(path), "wshd.sock");
  
  if(back_ground) {
    pid = fork();
    if(pid == 0) {//child ...
      /* Detach this process from its original group */
      w->fd = un_listen(path);
      rv = setsid();
      assert(rv > 0 && rv == getpid());
      return child_loop(w);
    }
    return 0;
  }
  w->fd = un_listen(path);
  return child_loop(w);
}

int main(int argc, char **argv) {
  wshd_t *w;
  int rv;

  w = calloc(1, sizeof(*w));
  assert(w != NULL);
  rv = wshd__getopt(w, argc, argv);
  if (rv == -1) {
    exit(1);
  }
  if (strlen(w->run_path) == 0) {
    strcpy(w->run_path, "run");
  }
  assert_directory(w->run_path);
  parent_run(w);
  return 0;
}
