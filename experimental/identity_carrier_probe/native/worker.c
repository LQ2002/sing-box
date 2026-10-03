// SPDX-License-Identifier: GPL-2.0-only
// Single-threaded fork and real exec fixtures, controlled by a private root
// registrar over inherited SOCK_SEQPACKET fd 3. Never receives a BPF map fd.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif
#define IPC 3
#define FD_BASE 100
#define MAX_SOCKETS 32
static const char payload[] = "identity-carrier-probe";

static void fail(const char *what)
{
    perror(what);
    _exit(1);
}

static unsigned long long start_ticks(void)
{
    char text[2048];
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("open stat");
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0) fail("read stat");
    text[n] = 0;
    char *end = strrchr(text, ')');
    if (!end || end[1] != ' ') fail("parse stat");
    char *save = NULL, *field = strtok_r(end + 2, " ", &save);
    for (int number = 3; field; number++, field = strtok_r(NULL, " ", &save)) {
        if (number == 22) return strtoull(field, NULL, 10);
    }
    fail("missing start ticks");
    return 0;
}

static void report(const char *op, unsigned id, int pass_fd)
{
    uint64_t cookie = 0;
    int kind = 0;
    char address[64] = "";
    if (id) {
        socklen_t size = sizeof(cookie);
        if (getsockopt(FD_BASE + (int)id, SOL_SOCKET, SO_COOKIE, &cookie, &size)) fail("SO_COOKIE");
        size = sizeof(kind);
        if (getsockopt(FD_BASE + (int)id, SOL_SOCKET, SO_TYPE, &kind, &size)) fail("SO_TYPE");
        struct sockaddr_in local;
        size = sizeof(local);
        if (getsockname(FD_BASE + (int)id, (struct sockaddr *)&local, &size)) fail("getsockname");
        if (local.sin_port) snprintf(address, sizeof(address), "127.0.0.1:%u", ntohs(local.sin_port));
    }
    char json[1024];
    int length = snprintf(json, sizeof(json),
        "{\"op\":\"%s\",\"PID\":%u,\"TID\":%u,\"UID\":%u,\"StartTicks\":%llu,"
        "\"SocketID\":%u,\"Family\":%u,\"SockType\":%u,\"Cookie\":%llu,\"address\":\"%s\"}",
        op, (unsigned)getpid(), (unsigned)syscall(SYS_gettid), (unsigned)getuid(),
        start_ticks(), id, id ? AF_INET : 0, kind, (unsigned long long)cookie, address);
    if (length <= 0 || (size_t)length >= sizeof(json)) fail("JSON length");
    struct iovec iov = { .iov_base = json, .iov_len = (size_t)length };
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
    if (pass_fd >= 0) {
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &pass_fd, sizeof(pass_fd));
    }
    ssize_t sent;
    do { sent = sendmsg(IPC, &msg, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    if (sent != length) fail("IPC sendmsg");
}

static void hello(const char *op)
{
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0) fail("pidfd_open self");
    report(op, 0, pidfd);
    close(pidfd);
}

static void command(char *buffer, size_t size)
{
    ssize_t n;
    do { n = recv(IPC, buffer, size - 1, MSG_TRUNC); } while (n < 0 && errno == EINTR);
    if (n <= 0 || (size_t)n >= size) fail("IPC command");
    buffer[n] = 0;
}

static int socket_fd(unsigned id)
{
    if (!id || id >= MAX_SOCKETS) { errno = EINVAL; fail("socket id"); }
    return FD_BASE + (int)id;
}

static void retain_socket(unsigned id, int fd)
{
    int target = socket_fd(id);
    if (fcntl(target, F_GETFD) >= 0 || errno != EBADF) fail("duplicate socket id");
    // Intentionally survives exec; ordinary sockets elsewhere use CLOEXEC.
    if (dup2(fd, target) != target) fail("dup2 socket");
    close(fd);
}

static void do_exec(void)
{
    execl("/proc/self/exe", "identity-native-worker", "after-exec", (char *)NULL);
    fail("exec self");
}

static void *thread_exec(void *unused)
{
    (void)unused;
    if (syscall(SYS_gettid) == getpid()) fail("thread exec ran on leader");
    report("exec_thread", 0, -1);
    char cmd[128];
    command(cmd, sizeof(cmd));
    if (strcmp(cmd, "CONTINUE")) fail("thread exec barrier");
    do_exec();
    return NULL;
}

static void loop(void)
{
    for (;;) {
        char cmd[128], tail;
        unsigned id, port, accepted;
        command(cmd, sizeof(cmd));
        if (sscanf(cmd, "CREATE %u %c", &id, &tail) == 1) {
            socket_fd(id);
            int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (fd < 0) fail("UDP socket");
            retain_socket(id, fd);
            report("create", id, socket_fd(id));
        } else if (sscanf(cmd, "REPORT %u %c", &id, &tail) == 1) {
            report("report", id, socket_fd(id));
        } else if (sscanf(cmd, "SEND %u %u %c", &id, &port, &tail) == 2) {
            if (!port || port > 65535) fail("loopback port");
            struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
            if (sendto(socket_fd(id), payload, sizeof(payload) - 1, MSG_NOSIGNAL,
                (struct sockaddr *)&dest, sizeof(dest)) != (ssize_t)sizeof(payload) - 1) fail("UDP send");
            report("sent", id, -1);
        } else if (sscanf(cmd, "LISTEN %u %c", &id, &tail) == 1) {
            socket_fd(id);
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0) fail("TCP socket");
            struct sockaddr_in local = { .sin_family = AF_INET,
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
            if (bind(fd, (struct sockaddr *)&local, sizeof(local)) || listen(fd, 4)) fail("listen");
            struct timeval tv = { .tv_sec = 5 };
            if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) fail("listen timeout");
            retain_socket(id, fd);
            report("listen", id, socket_fd(id));
        } else if (sscanf(cmd, "ACCEPT %u %u %c", &id, &accepted, &tail) == 2) {
            socket_fd(accepted);
            int fd = accept4(socket_fd(id), NULL, NULL, SOCK_CLOEXEC);
            if (fd < 0) fail("accept");
            retain_socket(accepted, fd);
            report("accept", accepted, socket_fd(accepted));
        } else if (sscanf(cmd, "WRITE %u %c", &id, &tail) == 1) {
            if (send(socket_fd(id), payload, sizeof(payload) - 1, MSG_NOSIGNAL) !=
                (ssize_t)sizeof(payload) - 1) fail("accepted socket write");
            report("sent", id, -1);
        } else if (!strcmp(cmd, "FORK")) {
            pid_t original = getpid();
            pid_t kid = fork();
            if (kid < 0) fail("fork");
            if (!kid) {
                if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != original) fail("fork parent lifetime");
                hello("fork_hello");
                continue;
            }
            int status;
            pid_t waited;
            do { waited = waitpid(kid, &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited != kid || !WIFEXITED(status) || WEXITSTATUS(status)) fail("fork child status");
            hello("parent_resumed");
        } else if (!strcmp(cmd, "EXEC")) {
            do_exec();
        } else if (!strcmp(cmd, "THREAD_EXEC")) {
            pthread_t thread;
            int err = pthread_create(&thread, NULL, thread_exec, NULL);
            if (err) { errno = err; fail("pthread_create"); }
            pthread_join(thread, NULL);
            fail("exec thread returned");
        } else if (!strcmp(cmd, "EXIT")) {
            report("exit", 0, -1);
            return;
        } else {
            errno = EINVAL;
            fail("unknown command");
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "start") && strcmp(argv[1], "after-exec"))) return 2;
    if (!strcmp(argv[1], "start") && getuid() == 0) {
        if (setgroups(0, NULL) || setresgid(2000, 2000, 2000) || setresuid(2000, 2000, 2000)) fail("drop credentials");
    }
    if (getuid() != 2000) fail("expected shell UID");
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() <= 1) fail("parent lifetime");
    struct timeval tv = { .tv_sec = 15 };
    if (setsockopt(IPC, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ||
        setsockopt(IPC, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))) fail("IPC timeout");
    hello(!strcmp(argv[1], "start") ? "hello" : "exec_hello");
    loop();
    return 0;
}
