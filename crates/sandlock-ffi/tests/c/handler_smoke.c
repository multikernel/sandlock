/* Canonical C example for sandlock's Handler ABI.
 *
 * Builds a sandbox, registers a single handler on SYS_getpid that
 * forces a synthetic return value of 777, runs the system python3
 * interpreter with an inline script that prints os.getpid(), and
 * asserts that the captured stdout contains "777".
 *
 * Downstream consumers writing C/Python/etc. bindings can copy this
 * file as a starting point.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "sandlock.h"

/* Exercise sandlock_action_set_inject_bytes() through the cdylib: the
 * default flags must produce an InjectFdSend whose fd reads back the bytes
 * and is sealed read-only; SANDLOCK_INJECT_WRITABLE must leave it unsealed.
 * Returns 0 on success, non-zero on failure. */
static int check_inject_bytes(void) {
    sandlock_action_out_t out;
    memset(&out, 0, sizeof out);

    const char *payload = "hello-from-c";
    size_t n = strlen(payload);
    sandlock_action_set_inject_bytes(&out, (const uint8_t *)payload, n, 0);

    if (out.kind != SANDLOCK_ACTION_INJECT_FD_SEND) {
        fprintf(stderr, "inject_bytes: kind=%u, want %d\n",
                out.kind, SANDLOCK_ACTION_INJECT_FD_SEND);
        return 1;
    }
    if (out.payload.inject_send.newfd_flags != (uint32_t)O_CLOEXEC) {
        fprintf(stderr, "inject_bytes: newfd_flags=%u, want O_CLOEXEC\n",
                out.payload.inject_send.newfd_flags);
        return 1;
    }
    int fd = out.payload.inject_send.srcfd;

    int seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0 || !(seals & F_SEAL_WRITE)) {
        fprintf(stderr, "inject_bytes: default fd not write-sealed (seals=%d)\n", seals);
        close(fd);
        return 1;
    }

    char buf[64] = {0};
    ssize_t got = pread(fd, buf, sizeof buf - 1, 0);
    close(fd);
    if (got != (ssize_t)n || memcmp(buf, payload, n) != 0) {
        fprintf(stderr, "inject_bytes: content mismatch (got=%zd)\n", got);
        return 1;
    }

    /* Writable variant: same content, but no write seal. */
    memset(&out, 0, sizeof out);
    sandlock_action_set_inject_bytes(&out, (const uint8_t *)payload, n,
                                     SANDLOCK_INJECT_WRITABLE);
    int wfd = out.payload.inject_send.srcfd;
    int wseals = fcntl(wfd, F_GET_SEALS);
    close(wfd);
    if (wseals >= 0 && (wseals & F_SEAL_WRITE)) {
        fprintf(stderr, "inject_bytes: WRITABLE fd unexpectedly write-sealed\n");
        return 1;
    }

    return 0;
}

static int force_getpid_to_777(
    void *ud,
    const sandlock_notif_data_t *notif,
    sandlock_mem_handle_t *mem,
    sandlock_action_out_t *out
) {
    (void)ud;
    (void)notif;
    (void)mem;
    sandlock_action_set_return_value(out, 777);
    return 0;
}

struct policy_ud {
    int magic;
    int drops;
};

static int policy_fn_record_ud(
    const sandlock_event_t *event,
    sandlock_ctx_t *ctx,
    void *ud
) {
    (void)ctx;
    struct policy_ud *state = (struct policy_ud *)ud;
    if (state == NULL || state->magic != 0x5150) {
        return 1;
    }
    (void)event;
    return 0;
}

static void policy_fn_drop_ud(void *ud) {
    struct policy_ud *state = (struct policy_ud *)ud;
    if (state != NULL && state->magic == 0x5150) {
        state->drops++;
    }
}

static int check_policy_fn_user_data_drop(void) {
    struct policy_ud state = {
        .magic = 0x5150,
        .drops = 0,
    };

    sandlock_builder_t *b = sandlock_sandbox_builder_new();
    b = sandlock_sandbox_builder_fs_read(b, "/usr");
    b = sandlock_sandbox_builder_fs_read(b, "/bin");
    b = sandlock_sandbox_builder_fs_read(b, "/lib");
    b = sandlock_sandbox_builder_fs_read(b, "/lib64");
    b = sandlock_sandbox_builder_fs_read(b, "/etc");
    b = sandlock_sandbox_builder_fs_read(b, "/proc");
    b = sandlock_sandbox_builder_fs_read(b, "/dev");
    b = sandlock_sandbox_builder_fs_write(b, "/tmp");
    b = sandlock_sandbox_builder_policy_fn(
        b, policy_fn_record_ud, &state, policy_fn_drop_ud);

    int err = 0;
    sandlock_sandbox_t *p = sandlock_sandbox_build(b, &err, NULL);
    if (p == NULL) {
        fprintf(stderr, "policy_fn: sandbox build failed: err=%d\n", err);
        return 1;
    }

    sandlock_sandbox_free(p);

    if (state.drops != 1) {
        fprintf(stderr, "policy_fn: user_data drop count=%d, want 1\n", state.drops);
        return 1;
    }
    return 0;
}

int main(void) {
    /* Pure-C check of the content-injection setter, independent of a live
     * sandbox run. */
    if (check_inject_bytes() != 0) {
        return 1;
    }
    if (check_policy_fn_user_data_drop() != 0) {
        return 1;
    }

    /* Build a sandbox that exposes just enough of the host for the
     * system python3 interpreter to start. Mirrors the read mounts used by
     * the live handler/proc runtime tests. */
    sandlock_builder_t *b = sandlock_sandbox_builder_new();
    b = sandlock_sandbox_builder_fs_read(b, "/usr");
    b = sandlock_sandbox_builder_fs_read(b, "/bin");
    b = sandlock_sandbox_builder_fs_read(b, "/lib");
    b = sandlock_sandbox_builder_fs_read(b, "/lib64");
    b = sandlock_sandbox_builder_fs_read(b, "/etc");
    b = sandlock_sandbox_builder_fs_read(b, "/proc");
    b = sandlock_sandbox_builder_fs_read(b, "/dev");
    b = sandlock_sandbox_builder_fs_write(b, "/tmp");

    int err = 0;
    sandlock_sandbox_t *p = sandlock_sandbox_build(b, &err, NULL);
    if (p == NULL) {
        fprintf(stderr, "sandlock: sandbox build failed: err=%d\n", err);
        return 1;
    }

    sandlock_handler_t *h = sandlock_handler_new(
        force_getpid_to_777, NULL, NULL, SANDLOCK_EXCEPTION_KILL);
    if (h == NULL) {
        fprintf(stderr, "sandlock: handler_new returned NULL\n");
        sandlock_sandbox_free(p);
        return 1;
    }

    sandlock_handler_registration_t regs[1] = {
        { .syscall_nr = SYS_getpid, .handler = h },
    };

    /* Invoke python3 directly (no `/usr/bin/env` shim) so the
     * interpreter does not chase venv pyvenv.cfg files outside the
     * sandbox's read allowlist. */
    const char *argv[] = {
        "/usr/bin/python3",
        "-c",
        "import os, sys; sys.stdout.write('GOT:' + str(os.getpid()))",
    };

    sandlock_result_t *rr = sandlock_run_with_handlers(
        p, NULL /* name: auto-generate sandbox-{pid} */, argv, 3, regs, 1);
    if (rr == NULL) {
        fprintf(stderr, "sandlock: run_with_handlers returned NULL\n");
        /* Per sandlock.h: on NULL return, do NOT free handler `h` —
         * ownership transfer state is undefined and freeing risks
         * double-free. The leak is bounded (one handler box). */
        sandlock_sandbox_free(p);
        return 1;
    }

    size_t len = 0;
    const uint8_t *stdout_bytes = sandlock_result_stdout_bytes(rr, &len);
    if (stdout_bytes == NULL) {
        fprintf(stderr, "sandlock: no stdout captured\n");
        sandlock_result_free(rr);
        sandlock_sandbox_free(p);
        return 1;
    }
    fwrite(stdout_bytes, 1, len, stdout);
    fputc('\n', stdout);

    int contains_777 =
        (memmem(stdout_bytes, len, "GOT:777", 7) != NULL);

    sandlock_result_free(rr);
    sandlock_sandbox_free(p);

    if (!contains_777) {
        fprintf(stderr, "expected 'GOT:777' in child stdout\n");
        return 1;
    }
    return 0;
}
