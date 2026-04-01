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
typedef void sandlock_policy_t;
typedef void sandlock_result_t;
typedef void sandlock_pipeline_t;

/* ----------------------------------------------------------------
 * Policy Builder
 * ---------------------------------------------------------------- */

sandlock_builder_t *sandlock_policy_builder_new(void);

/* Filesystem */
sandlock_builder_t *sandlock_policy_builder_fs_read(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_policy_builder_fs_write(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_policy_builder_fs_deny(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_policy_builder_workdir(sandlock_builder_t *b, const char *path);
sandlock_builder_t *sandlock_policy_builder_chroot(sandlock_builder_t *b, const char *path);

/* Resource limits */
sandlock_builder_t *sandlock_policy_builder_max_memory(sandlock_builder_t *b, uint64_t bytes);
sandlock_builder_t *sandlock_policy_builder_max_processes(sandlock_builder_t *b, uint32_t n);
sandlock_builder_t *sandlock_policy_builder_max_cpu(sandlock_builder_t *b, uint8_t pct);
sandlock_builder_t *sandlock_policy_builder_num_cpus(sandlock_builder_t *b, uint32_t n);

/* Network */
sandlock_builder_t *sandlock_policy_builder_net_allow_host(sandlock_builder_t *b, const char *host);
sandlock_builder_t *sandlock_policy_builder_net_bind_port(sandlock_builder_t *b, uint16_t port);
sandlock_builder_t *sandlock_policy_builder_net_connect_port(sandlock_builder_t *b, uint16_t port);
sandlock_builder_t *sandlock_policy_builder_port_remap(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_policy_builder_no_raw_sockets(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_policy_builder_no_udp(sandlock_builder_t *b, bool v);

/* Mode */
sandlock_builder_t *sandlock_policy_builder_privileged(sandlock_builder_t *b, bool v);

/* Isolation & determinism */
sandlock_builder_t *sandlock_policy_builder_isolate_ipc(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_policy_builder_isolate_signals(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_policy_builder_random_seed(sandlock_builder_t *b, uint64_t seed);
sandlock_builder_t *sandlock_policy_builder_clean_env(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_policy_builder_env_var(sandlock_builder_t *b, const char *key, const char *value);
sandlock_builder_t *sandlock_policy_builder_no_randomize_memory(sandlock_builder_t *b, bool v);
sandlock_builder_t *sandlock_policy_builder_no_huge_pages(sandlock_builder_t *b, bool v);

/* Build & free */
sandlock_policy_t *sandlock_policy_build(sandlock_builder_t *b, int *err);
void sandlock_policy_free(sandlock_policy_t *p);

/* ----------------------------------------------------------------
 * Run
 * ---------------------------------------------------------------- */

/** Run with captured stdout/stderr. Returns result handle (NULL on failure). */
sandlock_result_t *sandlock_run(const sandlock_policy_t *policy,
                                const char *const *argv, unsigned int argc);

/** Run with inherited stdio. Returns exit code (-1 on failure). */
int sandlock_run_interactive(const sandlock_policy_t *policy,
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
                                 const sandlock_policy_t *policy,
                                 const char *const *argv, unsigned int argc);

/** Run pipeline (consumes pipe). timeout_ms=0 means no timeout. */
sandlock_result_t *sandlock_pipeline_run(sandlock_pipeline_t *pipe, uint64_t timeout_ms);

void sandlock_pipeline_free(sandlock_pipeline_t *pipe);

#ifdef __cplusplus
}
#endif

#endif /* SANDLOCK_H */
