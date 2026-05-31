/**
 * sandlock C API — opaque handle bindings to sandlock-core.
 *
 * All pointer types are opaque handles. Free with the corresponding _free().
 * Builder functions consume and return the builder (move semantics).
 */

#ifndef SANDLOCK_H
#define SANDLOCK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle types */
typedef void sandlock_builder_t;
typedef void sandlock_sandbox_t;
typedef void sandlock_result_t;
typedef void sandlock_pipeline_t;

/* ----------------------------------------------------------------
 * Sandbox Builder
 * ---------------------------------------------------------------- */

sandlock_builder_t *sandlock_sandbox_builder_new(void);

/* Filesystem */
sandlock_builder_t *sandlock_sandbox_builder_fs_read(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_sandbox_builder_fs_write(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_sandbox_builder_fs_deny(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_sandbox_builder_workdir(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_sandbox_builder_chroot(sandlock_builder_t *b, const char *path);

/* Resource limits */
sandlock_builder_t *sandlock_sandbox_builder_max_memory(sandlock_builder_t *b, uint64_t bytes);
sandlock_builder_t *sandlock_sandbox_builder_max_processes(sandlock_builder_t *b, uint32_t n);
sandlock_builder_t *sandlock_sandbox_builder_max_cpu(sandlock_builder_t *b, uint8_t pct);
sandlock_builder_t *sandlock_sandbox_builder_num_cpus(sandlock_builder_t *b, uint32_t n);

/* Network */
/* `spec` is `host:port[,port,...]` (IP-restricted) or `:port` / `*:port`
 * (any IP). Validated when the sandbox is built. */
sandlock_builder_t *sandlock_sandbox_builder_net_allow(sandlock_builder_t *b, const char *spec);
sandlock_builder_t *sandlock_sandbox_builder_net_bind_port(sandlock_builder_t *b, uint16_t port);
sandlock_builder_t *sandlock_sandbox_builder_port_remap(sandlock_builder_t *b, bool v);
/* Protocol gating (UDP, ICMP) is expressed via net_allow rule schemes
 * (`udp://`, `icmp://`) — there are no separate boolean setters. */

/* Isolation & determinism */
sandlock_builder_t *sandlock_sandbox_builder_random_seed(sandlock_builder_t *b, uint64_t seed);
sandlock_builder_t *sandlock_sandbox_builder_clean_env(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_sandbox_builder_env_var(sandlock_builder_t *b, const char *key, const char *value);
sandlock_builder_t *sandlock_sandbox_builder_no_randomize_memory(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_sandbox_builder_no_huge_pages(sandlock_builder_t *b, bool v);

/* Build & free */
/* On failure, *err is set to -1 and *err_msg (if non-null) is set to a
 * heap-allocated C string with the error description. Caller frees it
 * via sandlock_string_free. Pass NULL for err_msg to discard. */
sandlock_sandbox_t *sandlock_sandbox_build(sandlock_builder_t *b,
                                           int *err,
                                           char **err_msg);
void sandlock_sandbox_free(sandlock_sandbox_t *p);
/* sandlock_string_free is declared further down — used for any
 * heap-allocated C string the FFI returns to the caller. */

/* ----------------------------------------------------------------
 * Run
 * ---------------------------------------------------------------- */

/** Run with captured stdout/stderr. Returns result handle (NULL on failure). */
/* name may be NULL to auto-generate as "sandbox-{pid}". */
sandlock_result_t *sandlock_run(const sandlock_sandbox_t *policy,
                                const char *name,
                                const char *const *argv, unsigned int argc);

/** Run with inherited stdio. Returns exit code (-1 on failure). */
/* name may be NULL to auto-generate as "sandbox-{pid}". */
int sandlock_run_interactive(const sandlock_sandbox_t *policy,
                             const char *name,
                             const char *const *argv, unsigned int argc);

/* ----------------------------------------------------------------
 * Result
 * ---------------------------------------------------------------- */

int sandlock_result_exit_code(const sandlock_result_t *r);
bool sandlock_result_success(const sandlock_result_t *r);

/** Get stdout as C string. Caller must free with sandlock_string_free(). */
char *sandlock_result_stdout(const sandlock_result_t *r);
/** Get stderr as C string. Caller must free with sandlock_string_free(). */
char *sandlock_result_stderr(const sandlock_result_t *r);

/** Get stdout as raw bytes. Returns pointer valid until result is freed. */
const uint8_t *sandlock_result_stdout_bytes(const sandlock_result_t *r, size_t *len);
/** Get stderr as raw bytes. */
const uint8_t *sandlock_result_stderr_bytes(const sandlock_result_t *r, size_t *len);

void sandlock_result_free(sandlock_result_t *r);
void sandlock_string_free(char *s);

/* ----------------------------------------------------------------
 * Pipeline
 * ---------------------------------------------------------------- */

sandlock_pipeline_t *sandlock_pipeline_new(void);

void sandlock_pipeline_add_stage(sandlock_pipeline_t *pipe,
                                 const sandlock_sandbox_t *policy,
                                 const char *const *argv, unsigned int argc);

/** Run pipeline (consumes pipe). timeout_ms=0 means no timeout. */
sandlock_result_t *sandlock_pipeline_run(sandlock_pipeline_t *pipe, uint64_t timeout_ms);

void sandlock_pipeline_free(sandlock_pipeline_t *pipe);

/* ----------------------------------------------------------------
 * Handler ABI — extension handlers for seccomp-notif syscalls.
 * ---------------------------------------------------------------- */

/** Snapshot of a kernel seccomp notification. Field layout must stay
 *  in lock-step with `sandlock_ffi::notif_repr::sandlock_notif_data_t`. */
typedef struct sandlock_notif_data_t {
    uint64_t id;
    uint32_t pid;
    uint32_t flags;
    int32_t  syscall_nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
} sandlock_notif_data_t;

/** Opaque child-memory accessor (lifetime: single callback invocation). */
typedef struct sandlock_mem_handle_t sandlock_mem_handle_t;

/** Read a NUL-terminated string. Returns 0 on success, -1 on failure.
 *  On success the buffer is NUL-terminated and `*out_len` holds the byte
 *  count copied (excluding NUL); `max_len` must be at least 1 to fit the
 *  NUL. */
int sandlock_mem_read_cstr(const sandlock_mem_handle_t *handle,
                           uint64_t addr,
                           uint8_t *buf, size_t max_len,
                           size_t *out_len);

/** Raw memory read. Returns 0/-1; `*out_len` holds actual bytes copied. */
int sandlock_mem_read(const sandlock_mem_handle_t *handle,
                      uint64_t addr,
                      uint8_t *buf, size_t len,
                      size_t *out_len);

/** Raw memory write. Returns 0/-1. */
int sandlock_mem_write(const sandlock_mem_handle_t *handle,
                       uint64_t addr,
                       const uint8_t *buf, size_t len);

typedef enum sandlock_action_kind {
    SANDLOCK_ACTION_UNSET                  = 0,
    SANDLOCK_ACTION_CONTINUE               = 1,
    SANDLOCK_ACTION_ERRNO                  = 2,
    SANDLOCK_ACTION_RETURN_VALUE           = 3,
    SANDLOCK_ACTION_INJECT_FD_SEND         = 4,
    SANDLOCK_ACTION_INJECT_FD_SEND_TRACKED = 5,
    SANDLOCK_ACTION_HOLD                   = 6,
    SANDLOCK_ACTION_KILL                   = 7,
} sandlock_action_kind_t;

typedef struct { int32_t sig; int32_t pgid; } sandlock_action_kill_t;

typedef struct {
    int32_t  srcfd;
    uint32_t newfd_flags;
} sandlock_action_inject_t;

typedef uint64_t sandlock_inject_tracker_t;

typedef struct {
    int32_t  srcfd;
    uint32_t newfd_flags;
    sandlock_inject_tracker_t tracker;
} sandlock_action_inject_tracked_t;

typedef union {
    uint64_t none;
    int32_t  errno_value;
    int64_t  return_value;
    sandlock_action_inject_t         inject_send;
    sandlock_action_inject_tracked_t inject_send_tracked;
    sandlock_action_kill_t           kill;
} sandlock_action_payload_t;

typedef struct sandlock_action_out_t {
    uint32_t kind;                       /* sandlock_action_kind_t */
    sandlock_action_payload_t payload;
} sandlock_action_out_t;

/* Setters — exactly one tag is written; the payload is filled in
 * accordingly. Calling a setter overwrites any prior setting. */
void sandlock_action_set_continue(sandlock_action_out_t *out);
void sandlock_action_set_errno(sandlock_action_out_t *out, int32_t errno_value);
void sandlock_action_set_return_value(sandlock_action_out_t *out, int64_t value);
/** Ownership of `srcfd` transfers from the caller to the supervisor
 *  only when the resulting action is actually dispatched. If the
 *  caller subsequently calls a different setter on the same
 *  `sandlock_action_out_t` (overwriting the kind tag before the
 *  supervisor reads it), `srcfd` is NOT closed and leaks. Pick one
 *  setter per action. */
void sandlock_action_set_inject_fd_send(sandlock_action_out_t *out,
                                        int32_t srcfd, uint32_t newfd_flags);
/* NOTE: `SANDLOCK_ACTION_INJECT_FD_SEND_TRACKED` (= 5) and
 * `sandlock_action_inject_tracked_t` are reserved for a future
 * tracker-aware inject variant. No setter is exposed in this release;
 * actions left with that kind tag are treated as `UNSET` and routed
 * through the handler's exception policy. */
void sandlock_action_set_hold(sandlock_action_out_t *out);
/** Kill action setter. `pgid == 0` is a sentinel: the supervisor
 *  substitutes the child process group id (resolved via getpgid(pid)
 *  on the notification's pid). To target a specific group, pass an
 *  explicit non-zero pgid.
 *
 *  If the supervisor cannot resolve a safe process group id for the
 *  child, the Kill action is refused and the notification is routed
 *  through the handler's exception policy instead. This happens when
 *  the notification pid is <= 0, when getpgid() fails, or when the
 *  resolved pgid collides with the supervisor's own group (all
 *  reachable in nested PID namespaces, e.g. Kubernetes pod-in-pod).
 *  An explicit non-zero pgid is likewise refused if it matches the
 *  supervisor's own process group. */
void sandlock_action_set_kill(sandlock_action_out_t *out, int32_t sig, int32_t pgid);

/** Policy applied when a handler callback fails to set a valid action:
 *  it returns non-zero, leaves the action UNSET, or panics across the
 *  FFI boundary (Rust handlers only). */
typedef enum sandlock_exception_policy {
    /** Kill the child process group with SIGKILL. Fail-closed, and the
     *  default. If no safe process group id is available for the child
     *  (see `sandlock_action_set_kill`), this degrades to failing the
     *  syscall with EPERM rather than risk signalling the supervisor's
     *  own process group. */
    SANDLOCK_EXCEPTION_KILL       = 0,
    /** Fail the syscall with EPERM. */
    SANDLOCK_EXCEPTION_DENY_EPERM = 1,
    /** Let the syscall continue unchanged (explicit fail-open). */
    SANDLOCK_EXCEPTION_CONTINUE   = 2,
    /** Fail the syscall with EIO. Idiomatic for audit-only handlers that
     *  propagate the failure as a plain OSError rather than
     *  PermissionError. */
    SANDLOCK_EXCEPTION_DENY_EIO   = 3,
} sandlock_exception_policy_t;

/** Opaque handler container.
 *
 * Ownership: allocated by `sandlock_handler_new` and freed by either
 * `sandlock_handler_free` (if never registered) or by the supervisor
 * after a successful or failed `sandlock_run_with_handlers` call.
 *
 * Thread safety: the supervisor MAY invoke the handler callback from
 * multiple worker threads concurrently across different notifications
 * (today's dispatch loop is largely serial; the public ABI makes no
 * concurrency guarantee, so a future dispatcher could parallelise
 * without breaking compatibility). The caller MUST ensure their `ud`
 * pointer is thread-safe — either immutable, or guarded by their own
 * synchronization primitives (atomics, mutex, etc.). Rust provides no
 * synchronization for an opaque `void*`. */
typedef struct sandlock_handler_t sandlock_handler_t;

/** C handler signature. Return 0 on success; a non-zero return triggers
 *  the handler's exception policy. The callee MUST call exactly one
 *  sandlock_action_set_*() on `out` before returning 0.
 *
 *  Thread safety: see `sandlock_handler_t` — this function may be
 *  invoked concurrently from multiple worker threads. Any state
 *  reachable through `ud` must be thread-safe. */
typedef int (*sandlock_handler_fn_t)(void *ud,
                                     const sandlock_notif_data_t *notif,
                                     sandlock_mem_handle_t *mem,
                                     sandlock_action_out_t *out);

typedef void (*sandlock_handler_ud_drop_t)(void *ud);

/** Allocate a handler container. Returns NULL when `handler_fn` is NULL
 *  or when `on_exception` is not one of the documented `SANDLOCK_EXCEPTION_*`
 *  values.
 *
 *  `ud` must be thread-safe to access — see `sandlock_handler_t` for
 *  the concurrency contract. `ud_drop`, if non-NULL, is invoked exactly
 *  once when the container is freed. */
sandlock_handler_t *sandlock_handler_new(sandlock_handler_fn_t handler_fn,
                                         void *ud,
                                         sandlock_handler_ud_drop_t ud_drop,
                                         sandlock_exception_policy_t on_exception);

/** Free a handler container that has not been handed to the supervisor. */
void sandlock_handler_free(sandlock_handler_t *h);

typedef struct sandlock_handler_registration_t {
    int64_t syscall_nr;
    sandlock_handler_t *handler; /* ownership transferred on a successful run */
} sandlock_handler_registration_t;

/** Run the policy with extra C handlers. Returns NULL on failure.
 *
 * `name` may be NULL to auto-generate as `sandbox-{pid}`, mirroring the
 * convention used by `sandlock_run`.
 *
 * Must not be called from a thread already running a Tokio runtime.
 * This function builds and drives its own runtime internally; calling
 * it from within an existing runtime panics, and the panic unwinds
 * across the FFI boundary via this function's `extern "C-unwind"` ABI.
 *
 * Ownership of every `registrations[i].handler` pointer transfers into
 * the call on entry. After this function returns, the caller MUST NOT
 * call `sandlock_handler_free` on any handler pointer that was passed
 * in — successful or not, the supervisor is responsible for freeing
 * the containers (which also invokes the registered `ud_drop`).
 *
 * Null handler pointers in the array are treated as a validation error
 * and the call returns NULL; non-null entries in the same array are
 * still freed by the supervisor (the array is consumed as a whole). */
sandlock_result_t *sandlock_run_with_handlers(
    const sandlock_sandbox_t *policy,
    const char *name,
    const char *const *argv, unsigned int argc,
    const sandlock_handler_registration_t *registrations,
    size_t nregistrations);

/** Interactive-stdio variant of `sandlock_run_with_handlers`. Returns
 * NULL on failure.
 *
 * `name` may be NULL to auto-generate as `sandbox-{pid}`, mirroring the
 * convention used by `sandlock_run_interactive`.
 *
 * Must not be called from a thread already running a Tokio runtime.
 * This function builds and drives its own runtime internally; calling
 * it from within an existing runtime panics, and the panic unwinds
 * across the FFI boundary via this function's `extern "C-unwind"` ABI.
 *
 * Ownership of every `registrations[i].handler` pointer transfers into
 * the call on entry. After this function returns, the caller MUST NOT
 * call `sandlock_handler_free` on any handler pointer that was passed
 * in — successful or not, the supervisor is responsible for freeing
 * the containers (which also invokes the registered `ud_drop`).
 *
 * Null handler pointers in the array are treated as a validation error
 * and the call returns NULL; non-null entries in the same array are
 * still freed by the supervisor (the array is consumed as a whole). */
sandlock_result_t *sandlock_run_interactive_with_handlers(
    const sandlock_sandbox_t *policy,
    const char *name,
    const char *const *argv, unsigned int argc,
    const sandlock_handler_registration_t *registrations,
    size_t nregistrations);

/** Resolve a syscall name (e.g. "openat") to its kernel syscall number
 * for the host architecture, for use as a `sandlock_handler_registration_t`
 * `syscall_nr`. Saves callers from hard-coding architecture-specific
 * numbers.
 *
 * Returns -1 if `name` is NULL, is not valid UTF-8, or names a syscall
 * sandlock does not know. The resolvable set covers the syscalls
 * sandlock filters or supervises; syscalls outside that set (e.g.
 * `getpid`) return -1 and must be registered by raw number. */
int64_t sandlock_syscall_nr(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* SANDLOCK_H */
