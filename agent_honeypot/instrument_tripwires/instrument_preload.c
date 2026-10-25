#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
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

static void absolute_path(int dirfd, const char *path, char *out, size_t size) {
    if (!path || !*path) { out[0] = '\0'; return; }
    if (path[0] == '/') { snprintf(out, size, "%s", path); return; }
    char base[PATH_MAX], fd_path[64];
    if (dirfd == AT_FDCWD) {
        if (syscall(SYS_getcwd, base, sizeof(base)) < 0) { out[0] = '\0'; return; }
    } else {
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
        ssize_t n = syscall(SYS_readlinkat, AT_FDCWD, fd_path, base, sizeof(base) - 1);
        if (n < 0) { out[0] = '\0'; return; }
        base[n] = '\0';
    }
    snprintf(out, size, "%s/%s", base, path);
}

static bool match_path(const char *path, const char *configured, bool prefix) {
    if (!path || !configured || !*configured) return false;
    size_t n = strlen(configured);
    return strcmp(path, configured) == 0 || (prefix && strncmp(path, configured, n) == 0 && path[n] == '/');
}

static const char *instrument_class(const char *path) {
    if (match_path(path, getenv("HONEYPOT_IN_TREE_EVENT_LOG"), false)) return "event_log";
    if (match_path(path, getenv("HONEYPOT_INSTRUMENT_REPORT_DIR"), true)
            || match_path(path, getenv("HONEYPOT_SCRATCH_REPORT"), false)) return "report";
    if (match_path(path, getenv("HONEYPOT_INSTRUMENT_MARKER"), false)) return "marker";
    if (match_path(path, getenv("HONEYPOT_INSTRUMENT_CORPUS"), false)) return "corpus";
    return NULL;
}

static void emit(const char *kind, const char *klass, const char *path) {
    if (in_hook) return;
    in_hook = 1;
    const char *fd_value = getenv("HONEYPOT_INSTRUMENT_FD");
    int fd = fd_value ? atoi(fd_value) : -1;
    if (fd >= 0) {
        struct timespec ts;
        char clean[PATH_MAX], line[PATH_MAX + 256];
        sanitize(clean, sizeof(clean), path);
        clock_gettime(CLOCK_REALTIME, &ts);
        int n = snprintf(line, sizeof(line), "%lld.%09ld\t%s\t%d\t0\tclass=%s path=%s blocked=%s\n",
            (long long)ts.tv_sec, ts.tv_nsec, kind, (int)getpid(), klass, clean,
            getenv("HONEYPOT_INSTRUMENT_OBSERVE_ONLY") ? "false" : "true");
        if (n > 0) (void)syscall(SYS_write, fd, line, (size_t)n);
    }
    in_hook = 0;
}

static bool inspect(int dirfd, const char *path, const char *kind) {
    char resolved[PATH_MAX];
    absolute_path(dirfd, path, resolved, sizeof(resolved));
    const char *klass = instrument_class(resolved);
    if (!klass) return false;
    emit(kind, klass, resolved);
    return getenv("HONEYPOT_INSTRUMENT_OBSERVE_ONLY") == NULL;
}

static mode_t optional_mode(int flags, va_list ap) {
    return (flags & (O_CREAT | O_TMPFILE)) ? (mode_t)va_arg(ap, int) : 0;
}

static bool writes(int flags) {
    return (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND));
}

int open(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = optional_mode(flags, ap); va_end(ap);
    if (writes(flags) && inspect(AT_FDCWD, path, "INSTRUMENT_TAMPER_WRITE")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
int open64(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = optional_mode(flags, ap); va_end(ap);
    if (writes(flags) && inspect(AT_FDCWD, path, "INSTRUMENT_TAMPER_WRITE")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
int openat(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = optional_mode(flags, ap); va_end(ap);
    if (writes(flags) && inspect(dirfd, path, "INSTRUMENT_TAMPER_WRITE")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
int openat64(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = optional_mode(flags, ap); va_end(ap);
    if (writes(flags) && inspect(dirfd, path, "INSTRUMENT_TAMPER_WRITE")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *);
    if (mode && strpbrk(mode, "wa+x") && inspect(AT_FDCWD, path, "INSTRUMENT_TAMPER_WRITE")) { errno = EPERM; return NULL; }
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(path, mode);
}
FILE *fopen64(const char *path, const char *mode) {
    static FILE *(*real_fopen64)(const char *, const char *);
    if (mode && strpbrk(mode, "wa+x") && inspect(AT_FDCWD, path, "INSTRUMENT_TAMPER_WRITE")) { errno = EPERM; return NULL; }
    if (!real_fopen64) real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    return real_fopen64(path, mode);
}
int unlink(const char *path) {
    if (inspect(AT_FDCWD, path, "INSTRUMENT_TAMPER_UNLINK")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
}
int unlinkat(int dirfd, const char *path, int flags) {
    if (inspect(dirfd, path, "INSTRUMENT_TAMPER_UNLINK")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_unlinkat, dirfd, path, flags);
}
static bool inspect_rename(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    bool block_old = inspect(olddirfd, oldpath, "INSTRUMENT_TAMPER_RENAME");
    bool block_new = inspect(newdirfd, newpath, "INSTRUMENT_TAMPER_RENAME");
    return block_old || block_new;
}
int rename(const char *oldpath, const char *newpath) {
    if (inspect_rename(AT_FDCWD, oldpath, AT_FDCWD, newpath)) { errno = EPERM; return -1; }
    return (int)syscall(SYS_renameat, AT_FDCWD, oldpath, AT_FDCWD, newpath);
}
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    if (inspect_rename(olddirfd, oldpath, newdirfd, newpath)) { errno = EPERM; return -1; }
    return (int)syscall(SYS_renameat, olddirfd, oldpath, newdirfd, newpath);
}
#ifdef SYS_renameat2
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    if (inspect_rename(olddirfd, oldpath, newdirfd, newpath)) { errno = EPERM; return -1; }
    return (int)syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}
#endif
