/*
 * rootfs-helper — minimal static binary for chroot integration tests.
 *
 * Compiled with: musl-gcc -static -O2 -o rootfs-helper rootfs-helper.c
 *
 * Implements a subset of coreutils commands needed by tests:
 *   echo, cat, ls, pwd, readlink, stat, mkdir, rmdir, true,
 *   sh (minimal: "echo ... > file", "cat file", chaining with && and ;)
 *
 * Also supports legacy syscall variants for testing the chroot dispatcher:
 *   legacy-stat, legacy-lstat, legacy-open, legacy-access, legacy-readlink
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ── echo ───────────────────────────────────────────────────── */
static int cmd_echo(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        if (i > 0) putchar(' ');
        fputs(argv[i], stdout);
    }
    putchar('\n');
    return 0;
}

/* ── cat ────────────────────────────────────────────────────── */
static int cmd_cat(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "cat: %s: %s\n", argv[i], strerror(errno));
            return 1;
        }
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            write(STDOUT_FILENO, buf, n);
        close(fd);
    }
    return 0;
}

/* ── ls ─────────────────────────────────────────────────────── */
static int cmd_ls(int argc, char **argv) {
    const char *path = argc > 0 ? argv[0] : ".";
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
        return 1;
    }
    struct dirent *ent;
    while ((ent = readdir(d)))
        if (ent->d_name[0] != '.' || (ent->d_name[1] && ent->d_name[1] != '.'))
            puts(ent->d_name);
    closedir(d);
    return 0;
}

/* ── pwd ────────────────────────────────────────────────────── */
static int cmd_pwd(void) {
    char buf[4096];
    if (getcwd(buf, sizeof(buf))) {
        puts(buf);
        return 0;
    }
    perror("pwd");
    return 1;
}

/* ── readlink ───────────────────────────────────────────────── */
static int cmd_readlink(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "readlink: missing operand\n"); return 1; }
    char buf[4096];
    ssize_t n = readlink(argv[0], buf, sizeof(buf) - 1);
    if (n < 0) {
        fprintf(stderr, "readlink: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    buf[n] = '\0';
    puts(buf);
    return 0;
}

/* ── stat ───────────────────────────────────────────────────── */
static int cmd_stat(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "stat: missing operand\n"); return 1; }
    struct stat st;
    if (stat(argv[0], &st) < 0) {
        fprintf(stderr, "stat: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    printf("size=%ld mode=%o\n", (long)st.st_size, st.st_mode & 07777);
    return 0;
}

/* ── mkdir ──────────────────────────────────────────────────── */
static int cmd_mkdir(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "mkdir: missing operand\n"); return 1; }
    if (mkdir(argv[0], 0755) < 0) {
        fprintf(stderr, "mkdir: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    return 0;
}

/* ── rmdir ──────────────────────────────────────────────────── */
static int cmd_rmdir(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "rmdir: missing operand\n"); return 1; }
    if (rmdir(argv[0]) < 0) {
        fprintf(stderr, "rmdir: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    return 0;
}

/* ── chmod ──────────────────────────────────────────────────── */
static int cmd_chmod(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "chmod: missing operand\n"); return 1; }
    unsigned mode;
    if (sscanf(argv[0], "%o", &mode) != 1) {
        fprintf(stderr, "chmod: invalid mode '%s'\n", argv[0]);
        return 1;
    }
    if (chmod(argv[1], mode) < 0) {
        fprintf(stderr, "chmod: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    return 0;
}

/* ── write (non-standard: write content to file) ────────────── */
static int cmd_write(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "write: usage: write <file> <content>\n"); return 1; }
    int fd = open(argv[0], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "write: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        if (i > 1) write(fd, " ", 1);
        write(fd, argv[i], strlen(argv[i]));
    }
    write(fd, "\n", 1);
    close(fd);
    return 0;
}

/* ── rm (unlink) ────────────────────────────────────────────── */
static int cmd_rm(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "rm: missing operand\n"); return 1; }
    if (unlink(argv[0]) < 0) {
        fprintf(stderr, "rm: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    return 0;
}

/* ── mv (rename) ────────────────────────────────────────────── */
static int cmd_mv(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "mv: missing operand\n"); return 1; }
    if (rename(argv[0], argv[1]) < 0) {
        fprintf(stderr, "mv: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    return 0;
}

/* ── ln -s (symlink) ────────────────────────────────────────── */
static int cmd_ln_s(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "ln: missing operand\n"); return 1; }
    if (symlink(argv[0], argv[1]) < 0) {
        fprintf(stderr, "ln: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    return 0;
}

/* ── access ─────────────────────────────────────────────────── */
static int cmd_access(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "access: missing operand\n"); return 1; }
    int mode = F_OK;
    if (argc >= 2) {
        mode = 0;
        for (const char *p = argv[1]; *p; p++) {
            if (*p == 'r') mode |= R_OK;
            else if (*p == 'w') mode |= W_OK;
            else if (*p == 'x') mode |= X_OK;
        }
    }
    if (access(argv[0], mode) < 0) {
        fprintf(stderr, "access: %s: %s\n", argv[0], strerror(errno));
        return 1;
    }
    printf("OK\n");
    return 0;
}

/* ── legacy syscall wrappers (for testing chroot handler) ──── */

static int cmd_legacy_stat(int argc, char **argv) {
    if (argc < 1) return 1;
    struct stat st;
    long ret = syscall(SYS_stat, argv[0], &st);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK size=%ld mode=%o\n", (long)st.st_size, st.st_mode & 07777);
    return 0;
}

static int cmd_legacy_lstat(int argc, char **argv) {
    if (argc < 1) return 1;
    struct stat st;
    long ret = syscall(SYS_lstat, argv[0], &st);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK size=%ld mode=%o type=%s\n", (long)st.st_size, st.st_mode & 07777,
           S_ISDIR(st.st_mode) ? "dir" : S_ISLNK(st.st_mode) ? "link" : "file");
    return 0;
}

static int cmd_legacy_open(int argc, char **argv) {
    if (argc < 1) return 1;
    int fd = (int)syscall(SYS_open, argv[0], O_RDONLY);
    if (fd < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    printf("OK ");
    if (n > 0) {
        write(STDOUT_FILENO, buf, n);
    }
    return 0;
}

static int cmd_legacy_access(int argc, char **argv) {
    if (argc < 1) return 1;
    long ret = syscall(SYS_access, argv[0], F_OK);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int cmd_legacy_readlink(int argc, char **argv) {
    if (argc < 1) return 1;
    char buf[4096];
    long n = syscall(SYS_readlink, argv[0], buf, sizeof(buf) - 1);
    if (n < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    buf[n] = '\0';
    printf("OK %s\n", buf);
    return 0;
}

static int cmd_legacy_mkdir(int argc, char **argv) {
    if (argc < 1) return 1;
    long ret = syscall(SYS_mkdir, argv[0], 0755);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int cmd_legacy_rmdir(int argc, char **argv) {
    if (argc < 1) return 1;
    long ret = syscall(SYS_rmdir, argv[0]);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int cmd_legacy_unlink(int argc, char **argv) {
    if (argc < 1) return 1;
    long ret = syscall(SYS_unlink, argv[0]);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int cmd_legacy_rename(int argc, char **argv) {
    if (argc < 2) return 1;
    long ret = syscall(SYS_rename, argv[0], argv[1]);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int cmd_legacy_symlink(int argc, char **argv) {
    if (argc < 2) return 1;
    long ret = syscall(SYS_symlink, argv[0], argv[1]);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int cmd_legacy_chmod(int argc, char **argv) {
    if (argc < 2) return 1;
    unsigned mode;
    if (sscanf(argv[0], "%o", &mode) != 1) return 1;
    long ret = syscall(SYS_chmod, argv[1], mode);
    if (ret < 0) {
        printf("ERR %d\n", errno);
        return 1;
    }
    printf("OK\n");
    return 0;
}

/* ── dispatch ───────────────────────────────────────────────── */

static int dispatch(const char *cmd, int argc, char **argv) {
    if (strcmp(cmd, "echo") == 0)           return cmd_echo(argc, argv);
    if (strcmp(cmd, "cat") == 0)            return cmd_cat(argc, argv);
    if (strcmp(cmd, "ls") == 0)             return cmd_ls(argc, argv);
    if (strcmp(cmd, "pwd") == 0)            return cmd_pwd();
    if (strcmp(cmd, "readlink") == 0)       return cmd_readlink(argc, argv);
    if (strcmp(cmd, "stat") == 0)           return cmd_stat(argc, argv);
    if (strcmp(cmd, "mkdir") == 0)          return cmd_mkdir(argc, argv);
    if (strcmp(cmd, "rmdir") == 0)          return cmd_rmdir(argc, argv);
    if (strcmp(cmd, "chmod") == 0)          return cmd_chmod(argc, argv);
    if (strcmp(cmd, "write") == 0)          return cmd_write(argc, argv);
    if (strcmp(cmd, "rm") == 0)             return cmd_rm(argc, argv);
    if (strcmp(cmd, "mv") == 0)             return cmd_mv(argc, argv);
    if (strcmp(cmd, "ln") == 0) {
        /* ln -s target link */
        if (argc >= 1 && strcmp(argv[0], "-s") == 0)
            return cmd_ln_s(argc - 1, argv + 1);
        fprintf(stderr, "ln: only -s supported\n");
        return 1;
    }
    if (strcmp(cmd, "access") == 0)         return cmd_access(argc, argv);
    if (strcmp(cmd, "true") == 0)           return 0;
    if (strcmp(cmd, "false") == 0)          return 1;

    /* Legacy syscall variants */
    if (strcmp(cmd, "legacy-stat") == 0)    return cmd_legacy_stat(argc, argv);
    if (strcmp(cmd, "legacy-lstat") == 0)   return cmd_legacy_lstat(argc, argv);
    if (strcmp(cmd, "legacy-open") == 0)    return cmd_legacy_open(argc, argv);
    if (strcmp(cmd, "legacy-access") == 0)  return cmd_legacy_access(argc, argv);
    if (strcmp(cmd, "legacy-readlink") == 0) return cmd_legacy_readlink(argc, argv);
    if (strcmp(cmd, "legacy-mkdir") == 0)   return cmd_legacy_mkdir(argc, argv);
    if (strcmp(cmd, "legacy-rmdir") == 0)   return cmd_legacy_rmdir(argc, argv);
    if (strcmp(cmd, "legacy-unlink") == 0)  return cmd_legacy_unlink(argc, argv);
    if (strcmp(cmd, "legacy-rename") == 0)  return cmd_legacy_rename(argc, argv);
    if (strcmp(cmd, "legacy-symlink") == 0) return cmd_legacy_symlink(argc, argv);
    if (strcmp(cmd, "legacy-chmod") == 0)   return cmd_legacy_chmod(argc, argv);

    fprintf(stderr, "rootfs-helper: unknown command '%s'\n", cmd);
    return 127;
}

/* ── minimal sh -c ──────────────────────────────────────────── */

/* Tokenize a command string into argv. Handles simple quoting. */
static int tokenize(char *s, char **tokens, int max) {
    int n = 0;
    while (*s && n < max - 1) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s || *s == '>' || *s == '&' || *s == ';') break;
        if (*s == '"') {
            s++;
            tokens[n++] = s;
            while (*s && *s != '"') s++;
            if (*s) *s++ = '\0';
        } else {
            tokens[n++] = s;
            while (*s && *s != ' ' && *s != '\t' && *s != '>'
                   && *s != '&' && *s != ';') s++;
            if (*s == ' ' || *s == '\t') *s++ = '\0';
        }
    }
    tokens[n] = NULL;
    return n;
}

/* Execute a single simple command, possibly with > redirection. */
static int exec_simple(char *cmdline) {
    /* Trim leading/trailing whitespace */
    while (*cmdline == ' ' || *cmdline == '\t') cmdline++;
    char *end = cmdline + strlen(cmdline) - 1;
    while (end > cmdline && (*end == ' ' || *end == '\t')) *end-- = '\0';
    if (!*cmdline) return 0;

    /* Check for > redirection */
    char *redir = NULL;
    for (char *p = cmdline; *p; p++) {
        if (*p == '>' && (p == cmdline || *(p-1) != '\\')) {
            *p = '\0';
            redir = p + 1;
            while (*redir == ' ') redir++;
            /* Trim trailing space from redirect target */
            char *re = redir + strlen(redir) - 1;
            while (re > redir && (*re == ' ' || *re == '\t')) *re-- = '\0';
            break;
        }
    }

    int saved_stdout = -1;
    if (redir && *redir) {
        int fd = open(redir, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            fprintf(stderr, "sh: cannot open %s: %s\n", redir, strerror(errno));
            return 1;
        }
        saved_stdout = dup(STDOUT_FILENO);
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }

    char *tokens[64];
    int n = tokenize(cmdline, tokens, 64);
    int ret = (n > 0) ? dispatch(tokens[0], n - 1, tokens + 1) : 0;

    if (saved_stdout >= 0) {
        fflush(stdout);
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    return ret;
}

/* Minimal shell: supports && and ; chaining. */
static int cmd_sh(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[0], "-c") != 0) {
        fprintf(stderr, "sh: only -c supported\n");
        return 1;
    }
    char *script = strdup(argv[1]);
    if (!script) return 1;

    int ret = 0;
    char *rest = script;
    while (rest && *rest) {
        /* Split on && or ; */
        char *and = strstr(rest, "&&");
        char *semi = strchr(rest, ';');
        char *split = NULL;
        int is_and = 0;

        if (and && (!semi || and < semi)) {
            split = and;
            is_and = 1;
        } else if (semi) {
            split = semi;
            is_and = 0;
        }

        char *cmd;
        if (split) {
            *split = '\0';
            cmd = rest;
            rest = split + (is_and ? 2 : 1);
        } else {
            cmd = rest;
            rest = NULL;
        }

        ret = exec_simple(cmd);
        if (is_and && ret != 0) break;
    }

    free(script);
    return ret;
}

/* ── main ───────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: rootfs-helper <command> [args...]\n");
        return 1;
    }

    /* Busybox-style: if invoked as "sh", "echo", etc., use argv[0] */
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];
    if (strcmp(base, "rootfs-helper") != 0 && strcmp(base, "helper") != 0) {
        if (strcmp(base, "sh") == 0)
            return cmd_sh(argc - 1, argv + 1);
        return dispatch(base, argc - 1, argv + 1);
    }

    /* Normal dispatch: first arg is the command */
    const char *cmd = argv[1];
    if (strcmp(cmd, "sh") == 0)
        return cmd_sh(argc - 2, argv + 2);
    return dispatch(cmd, argc - 2, argv + 2);
}
