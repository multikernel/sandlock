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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "sandlock.h"

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

int main(void) {
    /* Build a sandbox that exposes just enough of the host for the
     * system python3 interpreter to start. Mirrors the read mounts
     * from the Rust integration test in tests/handler_smoke.rs. */
    sandlock_builder_t *b = sandlock_sandbox_builder_new();
    b = sandlock_sandbox_builder_fs_read(b, "/usr");
    b = sandlock_sandbox_builder_fs_read(b, "/bin");
    b = sandlock_sandbox_builder_fs_read(b, "/lib");
    b = sandlock_sandbox_builder_fs_read(b, "/lib64");
    b = sandlock_sandbox_builder_fs_read(b, "/etc");
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
