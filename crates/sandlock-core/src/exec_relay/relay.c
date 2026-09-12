/*
 * exec-relay: freestanding program the supervisor execs in place of an
 * approved execve (x86_64, aarch64, riscv64).
 *
 * The supervisor cannot stop sandbox tasks from rewriting argv between its
 * policy check and the kernel's copy, so instead of continuing the original
 * execve it runs this program, which has a fresh private address space. The
 * argv and envp the policy approved travel in a trailer appended to this
 * program's own image, reachable through the fd the supervisor pinned; the
 * relay execs the real target with exactly that.
 *
 * Exit code 127 on any failure, with one line on stderr.
 */
typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;
typedef unsigned char u8;

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_fstat 5
#define SYS_pread64 17
#define SYS_execve 59
#define SYS_exit_group 231
#define SYS_openat 257
#define SYS_execveat 322
#define O_DIRECTORY 0200000
static i64 sc6(long n, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) {
    i64 r;
    register u64 r10 __asm__("r10") = d;
    register u64 r8  __asm__("r8")  = e;
    register u64 r9  __asm__("r9")  = f;
    __asm__ volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return r;
}
#elif defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_pread64 67
#define SYS_fstat 80
#define SYS_exit_group 94
#define SYS_execve 221
#define SYS_execveat 281
#define O_DIRECTORY 040000
#if defined(__aarch64__)
static i64 sc6(long n, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) {
    register long x8 __asm__("x8") = n;
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = d;
    register u64 x4 __asm__("x4") = e;
    register u64 x5 __asm__("x5") = f;
    __asm__ volatile("svc 0" : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory");
    return (i64)x0;
}
#else
static i64 sc6(long n, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) {
    register long nr __asm__("a7") = n;
    register u64 a0 __asm__("a0") = a;
    register u64 a1 __asm__("a1") = b;
    register u64 a2 __asm__("a2") = c;
    register u64 a3 __asm__("a3") = d;
    register u64 a4 __asm__("a4") = e;
    register u64 a5 __asm__("a5") = f;
    __asm__ volatile("ecall" : "+r"(a0)
        : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(nr)
        : "memory");
    return (i64)a0;
}
#endif
#else
#error "unsupported architecture"
#endif

#define SC1(n,a) sc6(n,(u64)(a),0,0,0,0,0)
#define SC2(n,a,b) sc6(n,(u64)(a),(u64)(b),0,0,0,0)
#define SC3(n,a,b,c) sc6(n,(u64)(a),(u64)(b),(u64)(c),0,0,0)
#define SC4(n,a,b,c,d) sc6(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),0,0)
#define SC5(n,a,b,c,d,e) sc6(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),0)

#define O_RDONLY 0
#define O_CLOEXEC 02000000
#define O_PATH 010000000
#define AT_FDCWD (-100)

#define TRAILER_MAGIC 0x52454c41u
#define TRAILER_VERSION 1u
#define ARGS_MAX (2u << 20)
#define ENTRIES_MAX 65536u

/* Patched by the supervisor in the image it builds for each exec; found in
 * the ELF bytes by the magic. Volatile so the initial values are never folded. */
struct config {
    u64 magic;
    u32 fd;
    u32 reserved;
    u64 trailer_off;
    u64 trailer_len;
};
__attribute__((used, section(".data")))
static volatile struct config config = { 0x5359414c45524c53ULL, 0, 0, 0, 0 };

struct hdr {
    u32 magic, version, mode, argc, envc, reserved;
    u64 dir_dev, dir_ino;
};

static u8 args_buf[ARGS_MAX];
static char *ptrs[2 * ENTRIES_MAX + 2];

/* GCC may still emit these for aggregate copies even with -fno-builtin. */
__attribute__((used)) void *memset(void *s, int c, unsigned long n) {
    u8 *p = s;
    while (n--) *p++ = (u8)c;
    return s;
}
__attribute__((used)) void *memcpy(void *d, const void *s, unsigned long n) {
    u8 *dp = d;
    const u8 *sp = s;
    while (n--) *dp++ = *sp++;
    return d;
}

static unsigned long slen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

static void put(const char *s) {
    SC3(SYS_write, 2, s, slen(s));
}

static void put_num(u64 v) {
    char b[24];
    int i = 23;
    b[i] = 0;
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    put(b + i);
}

static void die(const char *what, i64 ret) {
    put("sandlock exec-relay: ");
    put(what);
    if (ret < 0) {
        put(": errno ");
        put_num((u64)(-ret));
    }
    put("\n");
    SC1(SYS_exit_group, 127);
    for (;;) {}
}

/* Advance past one NUL-terminated string inside [p, end); NULL if unterminated. */
static const u8 *skip_str(const u8 *p, const u8 *end) {
    while (p < end && *p) p++;
    return p < end ? p + 1 : 0;
}

__attribute__((used, noinline))
static void relay_main(void) {
    u64 len = config.trailer_len;
    u64 off = config.trailer_off;
    int fd = (int)config.fd;
    if (len < sizeof(struct hdr) || len > ARGS_MAX) die("trailer size", 0);

    u64 got = 0;
    while (got < len) {
        i64 r = SC4(SYS_pread64, fd, args_buf + got, len - got, off + got);
        if (r <= 0) die("read trailer", r);
        got += (u64)r;
    }
    SC1(SYS_close, fd);

    struct hdr h;
    memcpy(&h, args_buf, sizeof h);
    if (h.magic != TRAILER_MAGIC || h.version != TRAILER_VERSION) die("trailer format", 0);
    if (h.argc > ENTRIES_MAX || h.envc > ENTRIES_MAX) die("trailer entries", 0);

    const u8 *end = args_buf + len;
    const u8 *p = args_buf + sizeof h;
    const char *dir = (const char *)p;
    if (!(p = skip_str(p, end))) die("trailer format", 0);
    const char *base = (const char *)p;
    if (!(p = skip_str(p, end))) die("trailer format", 0);
    const char *full = (const char *)p;
    if (!(p = skip_str(p, end))) die("trailer format", 0);

    u32 i;
    char **argv = ptrs;
    for (i = 0; i < h.argc; i++) {
        argv[i] = (char *)p;
        if (!(p = skip_str(p, end))) die("trailer format", 0);
    }
    argv[h.argc] = 0;
    char **envp = ptrs + h.argc + 1;
    for (i = 0; i < h.envc; i++) {
        envp[i] = (char *)p;
        if (!(p = skip_str(p, end))) die("trailer format", 0);
    }
    envp[h.envc] = 0;

    i64 r;
    if (h.mode == 0) {
        i64 dirfd = SC4(SYS_openat, AT_FDCWD, dir, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (dirfd < 0) die("open target directory", dirfd);
        /* st_dev and st_ino are the first two u64 of struct stat on all three arches. */
        u64 st[18];
        r = SC2(SYS_fstat, dirfd, st);
        if (r < 0) die("stat target directory", r);
        if (st[0] != h.dir_dev || st[1] != h.dir_ino) die("target directory changed", 0);
        r = SC5(SYS_execveat, dirfd, base, argv, envp, 0);
    } else {
        r = SC3(SYS_execve, full, argv, envp);
    }
    die("exec", r);
}

#if defined(__x86_64__)
__asm__(
    ".global _start\n"
    "_start:\n"
    "   xor %rbp, %rbp\n"
    "   and $-16, %rsp\n"
    "   call relay_main\n"
    "   hlt\n"
);
#elif defined(__aarch64__)
__asm__(
    ".global _start\n"
    "_start:\n"
    "   mov x29, #0\n"
    "   mov x30, #0\n"
    "   bl relay_main\n"
    "   brk #0\n"
);
#else
__asm__(
    ".global _start\n"
    "_start:\n"
    "   li fp, 0\n"
    "   li ra, 0\n"
    "   call relay_main\n"
    "   ebreak\n"
);
#endif
