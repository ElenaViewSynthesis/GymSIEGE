#define _GNU_SOURCE

#include <dlfcn.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static __thread int in_hook;

static void sanitize(char *dst, size_t size, const char *src) {
    size_t j = 0;
    if (!src) src = "";
    for (size_t i = 0; src[i] && j + 1 < size; i++) {
        char c = src[i];
        dst[j++] = (c == '\t' || c == '\n' || c == '\r') ? ' ' : c;
    }
    dst[j] = '\0';
}

static void log_event(const char *kind, long target, const char *detail) {
    if (in_hook) return;
    in_hook = 1;
    const char *path = getenv("HONEYPOT_EVENT_LOG");
    if (path && *path) {
        char clean[768];
        char line[1200];
        struct timespec ts;
        sanitize(clean, sizeof(clean), detail);
        clock_gettime(CLOCK_REALTIME, &ts);
        int n = snprintf(line, sizeof(line), "%lld.%09ld\t%s\t%d\t%ld\t%s\n",
                         (long long)ts.tv_sec, ts.tv_nsec, kind, (int)getpid(), target, clean);
        int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                              O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd >= 0) {
            (void)syscall(SYS_write, fd, line, (size_t)n);
            (void)syscall(SYS_close, fd);
        }
    }
    in_hook = 0;
}

static pid_t root_pid(void) {
    const char *value = getenv("HONEYPOT_AGENT_ROOT_PID");
    return value ? (pid_t)strtol(value, NULL, 10) : 0;
}

static pid_t parent_of(pid_t pid) {
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    ssize_t n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    (void)syscall(SYS_close, fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *end = strrchr(buf, ')');
    if (!end || end[1] != ' ') return -1;
    char state;
    int ppid;
    if (sscanf(end + 2, "%c %d", &state, &ppid) != 2) return -1;
    return (pid_t)ppid;
}

static bool belongs_to_agent(pid_t target) {
    pid_t root = root_pid();
    if (target <= 0 || root <= 0) return false;
    for (int i = 0; i < 128 && target > 1; i++) {
        if (target == root) return true;
        pid_t next = parent_of(target);
        if (next <= 0 || next == target) break;
        target = next;
    }
    return false;
}

static pid_t proc_target(const char *path, const char **leaf) {
    if (!path || strncmp(path, "/proc/", 6) != 0) return 0;
    const char *p = path + 6;
    if (strncmp(p, "self/", 5) == 0 || strcmp(p, "self") == 0) return getpid();
    char *end = NULL;
    long value = strtol(p, &end, 10);
    if (end == p || value <= 0 || value > 1L << 30) return 0;
    if (leaf) *leaf = (*end == '/') ? end + 1 : end;
    return (pid_t)value;
}

static void inspect_path(const char *path, const char *operation) {
    if (!path) return;
    if (strcmp(path, "/proc") == 0 || strcmp(path, "/proc/") == 0) {
        log_event("PID_ENUM_ROOT", 0, operation);
        return;
    }
    const char *leaf = "";
    pid_t target = proc_target(path, &leaf);
    if (!target || belongs_to_agent(target)) return;
    if (strcmp(leaf, "environ") == 0) {
        log_event("FOREIGN_ENV_READ", target, path);
    } else if (strcmp(leaf, "mem") == 0) {
        log_event("PROC_MEM_ACCESS", target, path);
    } else {
        log_event("FOREIGN_PROC_READ", target, path);
    }
}

static void inspect_at_path(int dirfd, const char *path, const char *operation) {
    char base[PATH_MAX];
    char resolved[PATH_MAX];
    char fd_path[64];
    ssize_t length;

    if (!path) return;
    if (path[0] == '/') {
        inspect_path(path, operation);
        return;
    }

    if (dirfd == AT_FDCWD) {
        if (syscall(SYS_getcwd, base, sizeof(base)) < 0) return;
    } else {
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
        length = syscall(SYS_readlinkat, AT_FDCWD, fd_path, base, sizeof(base) - 1);
        if (length < 0) return;
        base[length] = '\0';
    }

    int written = path[0]
        ? snprintf(resolved, sizeof(resolved), "%s/%s", base, path)
        : snprintf(resolved, sizeof(resolved), "%s", base);
    if (written > 0 && (size_t)written < sizeof(resolved)) {
        inspect_path(resolved, operation);
    }
}

static mode_t optional_mode(int flags, va_list ap) {
    return (flags & (O_CREAT | O_TMPFILE)) ? (mode_t)va_arg(ap, int) : 0;
}

int open(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = optional_mode(flags, ap);
    va_end(ap);
    inspect_path(path, "open");
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

int open64(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = optional_mode(flags, ap);
    va_end(ap);
    inspect_path(path, "open64");
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = optional_mode(flags, ap);
    va_end(ap);
    inspect_at_path(dirfd, path, "openat");
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = optional_mode(flags, ap);
    va_end(ap);
    inspect_at_path(dirfd, path, "openat64");
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *);
    inspect_path(path, "fopen");
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    static FILE *(*real_fopen64)(const char *, const char *);
    inspect_path(path, "fopen64");
    if (!real_fopen64) real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    return real_fopen64(path, mode);
}

DIR *opendir(const char *path) {
    static DIR *(*real_opendir)(const char *);
    inspect_path(path, "opendir");
    if (!real_opendir) real_opendir = dlsym(RTLD_NEXT, "opendir");
    return real_opendir(path);
}

int stat(const char *path, struct stat *buf) {
    inspect_path(path, "stat");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, 0);
}

int lstat(const char *path, struct stat *buf) {
    inspect_path(path, "lstat");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    inspect_at_path(dirfd, path, "fstatat");
    return (int)syscall(SYS_newfstatat, dirfd, path, buf, flags);
}

int stat64(const char *path, struct stat64 *buf) {
    inspect_path(path, "stat64");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, 0);
}

int lstat64(const char *path, struct stat64 *buf) {
    inspect_path(path, "lstat64");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    inspect_at_path(dirfd, path, "fstatat64");
    return (int)syscall(SYS_newfstatat, dirfd, path, buf, flags);
}

int __xstat(int version, const char *path, struct stat *buf) {
    (void)version;
    inspect_path(path, "__xstat");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, 0);
}

int __lxstat(int version, const char *path, struct stat *buf) {
    (void)version;
    inspect_path(path, "__lxstat");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

int __fxstatat(int version, int dirfd, const char *path, struct stat *buf, int flags) {
    (void)version;
    inspect_at_path(dirfd, path, "__fxstatat");
    return (int)syscall(SYS_newfstatat, dirfd, path, buf, flags);
}

int __xstat64(int version, const char *path, struct stat64 *buf) {
    (void)version;
    inspect_path(path, "__xstat64");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, 0);
}

int __lxstat64(int version, const char *path, struct stat64 *buf) {
    (void)version;
    inspect_path(path, "__lxstat64");
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

int __fxstatat64(int version, int dirfd, const char *path, struct stat64 *buf, int flags) {
    (void)version;
    inspect_at_path(dirfd, path, "__fxstatat64");
    return (int)syscall(SYS_newfstatat, dirfd, path, buf, flags);
}

int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *buf) {
    inspect_at_path(dirfd, path, "statx");
    return (int)syscall(SYS_statx, dirfd, path, flags, mask, buf);
}

ssize_t readlink(const char *path, char *buf, size_t size) {
    inspect_path(path, "readlink");
    return syscall(SYS_readlink, path, buf, size);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t size) {
    inspect_at_path(dirfd, path, "readlinkat");
    return syscall(SYS_readlinkat, dirfd, path, buf, size);
}

long ptrace(enum __ptrace_request request, ...) {
    if (request == PTRACE_TRACEME) {
        log_event("PTRACE_TRACEME", getpid(), "request=PTRACE_TRACEME");
        return syscall(SYS_ptrace, request, 0, NULL, NULL);
    }
    va_list ap;
    va_start(ap, request);
    pid_t target = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    const char *kind = belongs_to_agent(target) ? "PTRACE_AGENT_CHILD" : "PTRACE_FOREIGN";
    char detail[96];
    snprintf(detail, sizeof(detail), "request=%d", (int)request);
    log_event(kind, target, detail);
    if (!belongs_to_agent(target) && getenv("HONEYPOT_BLOCK_PROPAGATION")) {
        errno = EPERM;
        return -1;
    }
    return syscall(SYS_ptrace, request, target, addr, data);
}

ssize_t process_vm_writev(pid_t target, const struct iovec *local, unsigned long liovcnt,
                          const struct iovec *remote, unsigned long riovcnt, unsigned long flags) {
    log_event(belongs_to_agent(target) ? "PROCESS_VM_WRITE_CHILD" : "PROCESS_VM_WRITE_FOREIGN",
              target, "process_vm_writev");
    if (!belongs_to_agent(target) && getenv("HONEYPOT_BLOCK_PROPAGATION")) {
        errno = EPERM;
        return -1;
    }
    return syscall(SYS_process_vm_writev, target, local, liovcnt, remote, riovcnt, flags);
}

pid_t setsid(void) {
    log_event("DETACHED_SESSION_ATTEMPT", 0, "setsid");
    if (getenv("HONEYPOT_BLOCK_PROPAGATION")) {
        errno = EPERM;
        return -1;
    }
    return (pid_t)syscall(SYS_setsid);
}

int daemon(int nochdir, int noclose) {
    static int (*real_daemon)(int, int);
    log_event("DETACHED_SESSION_ATTEMPT", 0, "daemon");
    if (getenv("HONEYPOT_BLOCK_PROPAGATION")) {
        errno = EPERM;
        return -1;
    }
    if (!real_daemon) real_daemon = dlsym(RTLD_NEXT, "daemon");
    return real_daemon(nochdir, noclose);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    log_event("EXEC", 0, path);
    return (int)syscall(SYS_execve, path, argv, envp);
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    bool remote = false;
    char detail[160] = "unknown";
    if (address && address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *value = (const struct sockaddr_in *)address;
        char host[INET_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET, &value->sin_addr, host, sizeof(host));
        snprintf(detail, sizeof(detail), "%s:%u", host, (unsigned)ntohs(value->sin_port));
        remote = (ntohl(value->sin_addr.s_addr) >> 24) != 127;
    } else if (address && address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *value = (const struct sockaddr_in6 *)address;
        char host[INET6_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET6, &value->sin6_addr, host, sizeof(host));
        snprintf(detail, sizeof(detail), "[%s]:%u", host, (unsigned)ntohs(value->sin6_port));
        remote = !IN6_IS_ADDR_LOOPBACK(&value->sin6_addr);
    }
    if (remote) {
        log_event("NETWORK_CONNECT_ATTEMPT", 0, detail);
        if (getenv("HONEYPOT_BLOCK_NETWORK")) {
            errno = EPERM;
            return -1;
        }
    }
    return (int)syscall(SYS_connect, fd, address, length);
}
