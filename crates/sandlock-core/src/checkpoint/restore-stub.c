/*
 * restore-stub: freestanding self-restore stub (x86_64, riscv64).
 *
 * This is a core component of the checkpoint restore engine, not a test
 * fixture: the supervisor execs this stub into a fresh, fully-sandboxed process
 * to reconstruct a checkpoint. It is compiled by build.rs into OUT_DIR and its
 * path is exposed to the crate via the RESTORE_STUB_PATH env var.
 *
 * The stub is a dumb executor of the control blob built by
 * checkpoint/restore_blob.rs. Every decision (which regions to map, which fds
 * are restorable, where the vDSO must land, how to frame the FP image, whether
 * to re-arm an interrupted syscall) is made in Rust at serialize time.
 *
 * Sequence:
 *   1. read the vDSO base out of auxv, off the kernel-provided initial stack;
 *   2. read the control blob from CTRL_FD;
 *   3. mremap [vvar]/[vdso] onto the checkpoint-recorded bases;
 *   4. map every region MAP_FIXED (anon ones read/write for now);
 *   5. signal READY and wait for GO, while the supervisor writes the anonymous
 *      page contents in with process_vm_writev;
 *   6. mprotect the anonymous regions down to their checkpointed protections;
 *   7. unmap the leftovers of its own startup that the image did not overwrite;
 *   8. reopen the fd table at its saved numbers and offsets;
 *   9. (x86_64) restore fs_base/gs_base via arch_prctl; (riscv64) tp is carried
 *      in the signal frame gregs, so nothing to do;
 *  10. rt_sigreturn into the checkpoint's register context.
 *
 * Two address-space hazards drive the layout, and both are why this file avoids
 * anything the kernel would place for it:
 *
 *   - The stub's own image must not sit where a checkpoint region will be
 *     MAP_FIXED. It is linked at STUB_BASE (see build.rs and restore_blob.rs),
 *     far outside the range ordinary programs occupy; a -no-pie stub at the
 *     default 0x400000 collides with any static ET_EXEC workload. Rust refuses
 *     to build a blob whose regions overlap that window.
 *   - The kernel-provided initial stack sits where the checkpoint's [stack]
 *     usually goes, so _start switches to a private stack in .bss (inside the
 *     reserved window) before calling into C. auxv is read from the initial
 *     stack pointer, which _start passes along, before anything is mapped.
 *
 * The control blob is read into .bss rather than mapped for the same reason: a
 * kernel-placed mapping could be clobbered by a MAP_FIXED region.
 *
 * What survives into the restored process: the stub's own text/data/bss at
 * STUB_BASE. That is a few pages in a window the checkpoint provably does not
 * use, unlike the whole libc launcher the injection engine left behind.
 *
 * Built with: cc -static -nostdlib -no-pie -O2 -Wl,-Ttext-segment=STUB_BASE
 *
 * Exit codes (all _exit): 2 blob read, 3 bad magic/version/size, 4 map region,
 * 5 open region file, 6 ready write, 7 go read, 8 mprotect, 9 vdso mremap,
 * 10 fd reopen, 12 sweep entry overlapping the stub's own image, 13 arch_prctl
 * (x86_64 only). rt_sigreturn does not return; if it does, exit 11.
 */
#define CTRL_FD 3
#define READY_FD 4
#define GO_FD 5

/* The window this stub is linked into, mirroring restore_blob::STUB_BASE and
 * STUB_SPAN and the -Wl,-Ttext-segment= flag in build.rs. Used only to refuse a
 * sweep entry that would unmap the stub out from under itself. */
#ifdef __riscv
#define STUB_BASE 0x3000000000UL
#else
#define STUB_BASE 0x30000000000UL
#endif
#define STUB_SPAN 0x400000UL

#if defined(__riscv) && __riscv_xlen == 64
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_lseek 62
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_munmap 215
#define SYS_mremap 216
#define SYS_dup3 24
#define SYS_exit 93
#define SYS_openat 56
#define SYS_rt_sigreturn 139
/* No SYS_arch_prctl on riscv64 — tp is in the signal frame gregs. */
#elif __x86_64__
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_mremap 25
#define SYS_dup2 33
#define SYS_exit 60
#define SYS_openat 257
#define SYS_rt_sigreturn 15
#define SYS_arch_prctl 158
#else
#error "unsupported architecture"
#endif

/* x86_64 only: thread-pointer restore constants. */
#ifdef __x86_64__
#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#endif

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x2
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define AT_FDCWD (-100)
#define AT_SYSINFO_EHDR 33
#define SEEK_SET 0

/* Sized for the control blob of a large process: the region table costs 40
 * bytes per mapping and the string table one copy of each distinct mapped
 * path. Rust fails the restore rather than truncating if a blob exceeds it. */
#define CTRL_MAX (1 << 20)
/* Upper bound on a signal-frame FP image. x86_64: AMX-sized xstate plus
 * magic2. riscv64: 516 bytes, the last safe byte before sc_extdesc.reserved;
 * the kernel union __riscv_fp_state is 528 bytes. */
#if defined(__x86_64__)
#define FP_MAX 16384
#elif defined(__riscv) && __riscv_xlen == 64
#define FP_MAX 516
#endif
#define STACK_SIZE 65536
/* Leftover mappings the supervisor may ask the stub to unmap. A freshly
 * execve'd stub has only its own image and its startup stack, so this is far
 * above what a real restore produces; the supervisor fails rather than exceed
 * it (resume::MAX_SWEEP_ENTRIES). */
#define MAX_SWEEP 256

/* Expand a macro's value into a string, for use inside the module-level asm. */
#define STR_(x) #x
#define STR(x) STR_(x)

typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;
typedef unsigned char u8;

#ifdef __x86_64__
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
#elif defined(__riscv) && __riscv_xlen == 64
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
#define SC1(n,a) sc6(n,(u64)(a),0,0,0,0,0)
#define SC2(n,a,b) sc6(n,(u64)(a),(u64)(b),0,0,0,0)
#define SC3(n,a,b,c) sc6(n,(u64)(a),(u64)(b),(u64)(c),0,0,0)
#define SC4(n,a,b,c,d) sc6(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),0,0)
#define SC6(n,a,b,c,d,e,f) sc6(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),(u64)(f))

static void die(int code) { SC1(SYS_exit, code); for(;;){} }

/* -nostdlib leaves no libc, but the compiler may still lower a struct copy or
 * an initializing loop into a call to one of these, so define them here.
 * These bodies depend on -fno-tree-loop-distribute-patterns (see build.rs):
 * loop-idiom recognition otherwise rewrites each loop into a call to the very
 * function it is compiling, and the stub spins forever inside memset. */
void *memset(void *d, int c, unsigned long n) {
    unsigned char *p = d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}
void *memcpy(void *d, const void *s, unsigned long n) {
    unsigned char *p = d; const unsigned char *q = s;
    while (n--) *p++ = *q++;
    return d;
}

/* Blob layout mirror (little-endian; both x86_64 and riscv64 are LE, so native
 * struct reads work). Must match checkpoint/restore_blob.rs byte for byte. */
struct blob_header {
    u32 magic, version, n_regions, n_fds;
    u64 regs_off; u32 regs_len, fpstate_len;
    u64 fpstate_off;
    u64 strings_off; u32 strings_len, n_vdso;
    u64 vdso_off;
};
struct blob_region {
    u64 start, end; u32 prot; unsigned char src, _p0[3]; u64 file_off;
    u32 path_off, _p1;
};
struct blob_fd { u32 fd, flags; u64 offset; u32 path_off, _p0; };
struct blob_vdso { i64 delta; u64 len; u64 target; };

#define BLOB_MAGIC 0x534c5242u
#define BLOB_VERSION 2u
#define SRC_ANON 0
#define SRC_FILE 1

/* ---- Architecture-specific signal frame layouts --------------------------
 * The stub builds the frame on its private stack and rt_sigreturns into it.
 * Registers in the blob are in ptrace order (capture::ptrace_getregs). */

#ifdef __x86_64__

/* x86_64: rt_sigreturn reads the ucontext at rsp (kernel does frame = rsp - 8;
 * uc is at frame+8 = rsp). We build a ucontext, set rsp to &uc, and syscall
 * rt_sigreturn. mcontext gregs order: see REG_* below. */
enum { R8=0,R9,R10,R11,R12,R13,R14,R15,RDI,RSI,RBP,RBX,RDX,RAX,RCX,RSP,RIP,
       EFL,CSGSFS,ERR,TRAPNO,OLDMASK,CR2 }; /* 23 gregs */
struct sigctx { u64 gregs[23]; u64 fpstate; u64 reserved[8]; };
struct uctx {
    u64 uc_flags;      /* 0 */
    u64 uc_link;       /* 8 */
    u64 ss_sp; u32 ss_flags; u32 _pad; u64 ss_size; /* uc_stack @16, 24 bytes */
    struct sigctx mc;  /* uc_mcontext @40 */
    u64 uc_sigmask[16];/* 128-byte sigset */
};

/* Captured user_regs_struct order (27 u64), matching capture::ptrace_getregs.
 *
 * The signal frame carries 23 of these. Accounting for the other four, because
 * silently dropping one costs a resumed program that dies with no explanation:
 * fs_base and gs_base have no slot in the frame and are restored separately with
 * arch_prctl (step 9); ds and es are ignored under the x86_64 flat memory model;
 * and orig_rax is consumed in Rust, which uses it to re-arm an interrupted
 * syscall before serializing rip and rax (see restore_blob.rs). */
enum { UR_R15=0,UR_R14,UR_R13,UR_R12,UR_RBP,UR_RBX,UR_R11,UR_R10,UR_R9,UR_R8,
       UR_RAX,UR_RCX,UR_RDX,UR_RSI,UR_RDI,UR_ORIG_RAX,UR_RIP,UR_CS,UR_EFLAGS,
       UR_RSP,UR_SS,UR_FS_BASE,UR_GS_BASE,UR_DS,UR_ES,UR_FS,UR_GS };

#elif defined(__riscv) && __riscv_xlen == 64

/* riscv64: rt_sigreturn reads frame at sp = (struct rt_sigframe *)sp.
 * siginfo (128 bytes) + ucontext. uc_mcontext is at uc+0xB0 (176).
 * sc_regs[32] at sigcontext+0x00, sc_fpregs at sigcontext+0x100;
 * sigcontext is 16-aligned, hence the pad from 0xA8 to 0xB0.
 * The gp[] blob order is ptrace: pc=0, ra=1, sp=2, gp=3, tp=4, t0-t2=5-7,
 * s0-s1=8-9, a0-a7=10-17, s2-s11=18-27, t3-t6=28-31 — a 1:1 mapping to
 * sc_regs[32], so no remap is needed. tp (thread pointer) is carried by the
 * signal frame's sc_regs[4]; nothing needs arch_prctl. */
struct sigctx {
    u64 gregs[32];           /* sc_regs: 32 gregs, 256 bytes */
    u8  fpregs[528];         /* sc_fpregs: union __riscv_fp_state (kernel 528 byte union) */
};

/* The sc_fpregs memcpy is bounded only by validate's FP_MAX check. */
_Static_assert(FP_MAX <= sizeof((struct sigctx){0}.fpregs),
               "FP_MAX must not exceed sc_fpregs");

struct uctx {
    u64 uc_flags;            /* 0x00 */
    u64 uc_link;             /* 0x08 */
    u64 ss_sp;               /* 0x10 */
    u32 ss_flags;            /* 0x18 */
    u32 _pad;                /* 0x1C */
    u64 ss_size;             /* 0x20 */
    u64 uc_sigmask;          /* 0x28 */
    u8  __unused[128];       /* 0x30 */
    struct sigctx mc;        /* 0xB0 (176) */
};

/* rt_sigframe: struct siginfo (zeroed, 128 bytes) + ucontext. */
struct rt_sf {
    u8 info[128];
    struct uctx uc;
};

#endif

/* These all live in .bss at STUB_BASE, out of reach of any MAP_FIXED region.
 * stub_stack is global so the module-level asm below can reference it. */
static char ctrl_buf[CTRL_MAX] __attribute__((aligned(16)));
#ifdef __x86_64__
/* xrstor requires the signal frame's FP image to be 64-byte aligned. */
static char fp_buf[FP_MAX] __attribute__((aligned(64)));
#endif
/* Interleaved (start, len) pairs of the mappings to shed. */
static u64 sweep[MAX_SWEEP * 2];
char stub_stack[STACK_SIZE];

/* Read exactly `len` bytes; a pipe hands them over in whatever chunks it likes. */
static int read_full(int fd, void *dst, u64 len) {
    u64 done = 0;
    while (done < len) {
        i64 r = SC3(SYS_read, fd, (char *)dst + done, len - done);
        if (r <= 0) return 0;
        done += (u64)r;
    }
    return 1;
}

/* Relocate one kernel special mapping onto its checkpoint-recorded base. */
static void move_special(const struct blob_vdso *v, u64 vdso_base) {
    u64 cur = (u64)((i64)vdso_base + v->delta);
    if (cur == v->target) return;
    i64 r = SC6(SYS_mremap, cur, v->len, v->len,
                MREMAP_MAYMOVE | MREMAP_FIXED, v->target, 0);
    if ((u64)r != v->target) die(9);
}

/* `used`: the only reference is the module-level asm `call _start_c`, which the
 * optimizer cannot see, so without this -O2 would eliminate the function. */
__attribute__((used, noinline))
static void _start_c(u64 *sp) {
    u32 i;

    /* 1. Find the fresh vDSO base in auxv, before anything unmaps the initial
     * stack it lives on. Stack layout: argc, argv[], NULL, envp[], NULL, auxv
     * pairs, AT_NULL. [vvar] has no auxv entry of its own; its base is derived
     * from the vDSO base and the checkpoint-recorded delta. */
    u64 *p = sp + 1 + sp[0] + 1;
    while (*p) p++;
    p++;
    u64 vdso_base = 0;
    for (; p[0]; p += 2) if (p[0] == AT_SYSINFO_EHDR) vdso_base = p[1];

    /* 2. Read the control blob. Read, not mmap: a kernel-placed mapping could
     * be clobbered by one of the MAP_FIXED regions below. */
    u64 n = 0;
    for (;;) {
        i64 r = SC3(SYS_read, CTRL_FD, ctrl_buf + n, CTRL_MAX - n);
        if (r < 0) die(2);
        if (r == 0) break;
        n += (u64)r;
        if (n == CTRL_MAX) die(3); /* blob larger than the buffer */
    }
    /* Bounds-check every section against what was actually read, so a blob that
     * disagrees with this stub (a version skew the magic did not catch, a short
     * write) fails here rather than by reading past the buffer. */
    struct blob_header *h = (struct blob_header *)ctrl_buf;
    if (n < sizeof(struct blob_header)) die(3);
    if (h->magic != BLOB_MAGIC || h->version != BLOB_VERSION) die(3);
    u64 tables = sizeof(struct blob_header)
               + (u64)h->n_regions * sizeof(struct blob_region)
               + (u64)h->n_fds * sizeof(struct blob_fd)
               + (u64)h->n_vdso * sizeof(struct blob_vdso);
    if (tables > n) die(3);
    if (h->vdso_off + (u64)h->n_vdso * sizeof(struct blob_vdso) > n) die(3);
    if (h->strings_off + h->strings_len > n) die(3);
    if (h->regs_off + h->regs_len > n) die(3);
    if (h->fpstate_off + h->fpstate_len > n) die(3);
    if (h->fpstate_len > FP_MAX) die(3);

    struct blob_region *regions =
        (struct blob_region *)(ctrl_buf + sizeof(struct blob_header));
    struct blob_fd *fds = (struct blob_fd *)&regions[h->n_regions];
    struct blob_vdso *vdso = (struct blob_vdso *)(ctrl_buf + h->vdso_off);
    const char *strings = ctrl_buf + h->strings_off;
    u64 *gp = (u64 *)(ctrl_buf + h->regs_off);

    /* 3. Move [vvar]/[vdso] onto the recorded bases, before any MAP_FIXED can
     * land on them. glibc/musl cache vDSO function pointers (clock_gettime,
     * getcpu, ...) at the checkpoint-era base; without this a restored program
     * jumps to an address the fresh kernel mapped elsewhere under ASLR and
     * faults on its first vDSO call. Same-kernel restore only: the vDSO code is
     * byte-identical, so relocating it makes every cached pointer valid.
     *
     * The whole block shifts by one constant amount, so walking the ascending
     * table backwards when shifting up (and forwards when shifting down) never
     * overwrites a source that has not been relocated yet. */
    if (h->n_vdso && vdso_base) {
        i64 shift = (i64)vdso[0].target - ((i64)vdso_base + vdso[0].delta);
        if (shift > 0)
            for (i = h->n_vdso; i-- > 0;) move_special(&vdso[i], vdso_base);
        else if (shift < 0)
            for (i = 0; i < h->n_vdso; i++) move_special(&vdso[i], vdso_base);
    }

    /* 4. Rebuild every region. Anonymous regions are mapped read/write so the
     * supervisor's process_vm_writev can fill them (that call honours the VMA's
     * protections), and are narrowed to their checkpointed protections in
     * step 6. File-backed regions take their final protections here: their
     * contents come from the file, so nothing writes to them. */
    for (i = 0; i < h->n_regions; i++) {
        struct blob_region *r = &regions[i];
        u64 len = r->end - r->start;
        i64 p;
        if (r->src == SRC_ANON) {
            p = SC6(SYS_mmap, r->start, len, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        } else {
            i64 fd = SC4(SYS_openat, AT_FDCWD, strings + r->path_off, 0 /*O_RDONLY*/, 0);
            if (fd < 0) die(5);
            p = SC6(SYS_mmap, r->start, len, r->prot,
                    MAP_PRIVATE | MAP_FIXED, fd, r->file_off);
            SC1(SYS_close, fd);
        }
        if ((u64)p != r->start) die(4);
    }

    /* 5. READY: the address space is laid out. The supervisor writes the
     * anonymous page contents in, then answers with the GO message: a count of
     * leftover mappings followed by that many (start, len) pairs. Those are the
     * mappings the kernel made for the stub's own startup (its initial stack
     * above all) that the checkpoint image did not overwrite; the supervisor
     * diffs /proc against the checkpoint to find them, because it can read
     * /proc unconfined and the stub cannot. */
    u64 one = 1;
    if (SC3(SYS_write, READY_FD, &one, 8) != 8) die(6);
    u64 n_sweep = 0;
    if (!read_full(GO_FD, &n_sweep, 8)) die(7);
    if (n_sweep > MAX_SWEEP) die(7);
    if (n_sweep && !read_full(GO_FD, sweep, n_sweep * 16)) die(7);

    /* 6. Narrow the anonymous regions to their checkpointed protections. */
    for (i = 0; i < h->n_regions; i++) {
        struct blob_region *r = &regions[i];
        if (r->src != SRC_ANON) continue;
        if (r->prot == (PROT_READ | PROT_WRITE)) continue;
        if (SC3(SYS_mprotect, r->start, r->end - r->start, r->prot) != 0) die(8);
    }

    /* 7. Shed the leftovers. The stub runs on its own .bss stack inside the
     * reserved window and the supervisor never puts that window on the list, so
     * nothing the stub is standing on should be here. Check it anyway rather
     * than trust the peer: unmapping our own text or stack faults instantly and
     * indistinguishably from a bad restore image, which is a miserable thing to
     * debug on a host you cannot reproduce. */
    for (i = 0; i < (u32)n_sweep; i++) {
        u64 start = sweep[2 * i], len = sweep[2 * i + 1];
        if (start < STUB_BASE + STUB_SPAN && STUB_BASE < start + len) die(12);
        SC2(SYS_munmap, start, len);
    }

    /* 8. Reopen the fd table. The control fds go first: a restored fd number
     * may well be 3, 4 or 5, and nothing needs them from here on. */
    SC1(SYS_close, CTRL_FD);
    SC1(SYS_close, READY_FD);
    SC1(SYS_close, GO_FD);
    for (i = 0; i < h->n_fds; i++) {
        struct blob_fd *f = &fds[i];
        i64 fd = SC4(SYS_openat, AT_FDCWD, strings + f->path_off, f->flags, 0);
        if (fd < 0) die(10);
        if ((u32)fd != f->fd) {
#if defined(__riscv) && __riscv_xlen == 64
            /* riscv64 has no SYS_dup2 — use dup3 with flags=0. */
            if (SC3(SYS_dup3, fd, f->fd, 0) != (i64)f->fd) die(10);
#else
            if (SC2(SYS_dup2, fd, f->fd) != (i64)f->fd) die(10);
#endif
            SC1(SYS_close, fd);
        }
        SC3(SYS_lseek, f->fd, f->offset, SEEK_SET);
    }

#ifdef __x86_64__
    /* 9. Restore the thread pointer. The x86_64 signal frame has 23 gregs and
     * none of them is fs_base, so rt_sigreturn cannot carry it and the resumed
     * program would inherit this stub's, which is zero because a -nostdlib
     * binary never sets one. Every libc addresses thread-local storage through
     * %fs, so the first TLS access faults: with glibc that is the stack-protector
     * canary at %fs:0x28, read on entry to almost every function, so the program
     * dies immediately with a bare SIGSEGV. (The ptrace engine this replaced got
     * this for free, since PTRACE_SETREGS writes fs_base.) gs_base is zero for
     * ordinary user programs; set it only when the checkpoint recorded one. */
    if (SC2(SYS_arch_prctl, ARCH_SET_FS, gp[UR_FS_BASE]) != 0) die(13);
    if (gp[UR_GS_BASE] && SC2(SYS_arch_prctl, ARCH_SET_GS, gp[UR_GS_BASE]) != 0) die(13);
#endif

    /* 10. Build the rt_sigframe on our private stack and rt_sigreturn into the
     * checkpoint. The frame must be readable when the kernel consumes it; the
     * stub stack is a plain .bss mapping at STUB_BASE, so it always is. */
#ifdef __x86_64__
    struct uctx uc;
    memset(&uc, 0, sizeof uc);
    struct sigctx *m = &uc.mc;
    m->gregs[R8]  = gp[UR_R8];  m->gregs[R9]  = gp[UR_R9];
    m->gregs[R10] = gp[UR_R10]; m->gregs[R11] = gp[UR_R11];
    m->gregs[R12] = gp[UR_R12]; m->gregs[R13] = gp[UR_R13];
    m->gregs[R14] = gp[UR_R14]; m->gregs[R15] = gp[UR_R15];
    m->gregs[RDI] = gp[UR_RDI]; m->gregs[RSI] = gp[UR_RSI];
    m->gregs[RBP] = gp[UR_RBP]; m->gregs[RBX] = gp[UR_RBX];
    m->gregs[RDX] = gp[UR_RDX]; m->gregs[RAX] = gp[UR_RAX];
    m->gregs[RCX] = gp[UR_RCX]; m->gregs[RSP] = gp[UR_RSP];
    m->gregs[RIP] = gp[UR_RIP]; m->gregs[EFL] = gp[UR_EFLAGS];
    /* CSGSFS packs cs(0:15), gs(16:31), fs(32:47), ss(48:63). */
    m->gregs[CSGSFS] = (gp[UR_CS] & 0xffff)
                     | ((gp[UR_GS] & 0xffff) << 16)
                     | ((gp[UR_FS] & 0xffff) << 32)
                     | ((gp[UR_SS] & 0xffff) << 48);

    /* The FP image arrives already framed for the kernel (magic words and
     * sw_reserved filled in by restore_blob.rs); copy it somewhere 64-byte
     * aligned and point the frame at it. An empty image means "no FP state",
     * which fpstate = 0 tells the kernel. */
    if (h->fpstate_len) {
        memcpy(fp_buf, ctrl_buf + h->fpstate_off, h->fpstate_len);
        m->fpstate = (u64)fp_buf;
    } else {
        m->fpstate = 0;
    }

    /* Set rsp = &uc, then syscall rt_sigreturn. */
    register u64 rax __asm__("rax") = SYS_rt_sigreturn;
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "syscall\n\t"
        :
        : "r"(&uc), "r"(rax)
        : "memory");

#elif defined(__riscv) && __riscv_xlen == 64
    /* riscv64: build a struct rt_sigframe on the stack. gp[] order is 1:1 with
     * sc_regs (both ptrace order), so copy the register file directly.
     * The FP state is embedded inline in sc_fpregs (no pointer indirection,
     * no magic framing — restore_blob.rs sends the raw __riscv_d_ext_state). */
    struct rt_sf sf;
    memset(&sf, 0, sizeof sf);
    /* gp has regs_len / 8 entries; copy all of them into sc_regs[32]. */
    u32 nregs = h->regs_len / 8;
    if (nregs > 32) nregs = 32;
    memcpy(sf.uc.mc.gregs, gp, nregs * sizeof(u64));
    if (h->fpstate_len) {
        memcpy(sf.uc.mc.fpregs, ctrl_buf + h->fpstate_off, h->fpstate_len);
    }

    /* Set sp = &sf, then ecall rt_sigreturn. */
    register u64 a7 __asm__("a7") = SYS_rt_sigreturn;
    __asm__ volatile(
        "mv sp, %0\n\t"
        "ecall\n\t"
        :
        : "r"(&sf), "r"(a7)
        : "memory");
#endif
    die(11); /* rt_sigreturn must not return */
}

/* No libc: provide the ELF entry. Hand the kernel-provided stack pointer to
 * _start_c as its argument (auxv lives there), then switch to the private .bss
 * stack, because the checkpoint's [stack] region is mapped over the address the
 * kernel picked for ours. */
#ifdef __x86_64__
__asm__(
    ".global _start\n"
    "_start:\n"
    "   xor %rbp, %rbp\n"
    "   mov %rsp, %rdi\n"
    "   lea stub_stack(%rip), %rsp\n"
    "   add $" STR(STACK_SIZE) ", %rsp\n"
    "   and $-16, %rsp\n"
    "   call _start_c\n"
    "   hlt\n"
);
#elif defined(__riscv) && __riscv_xlen == 64
/* riscv64: a0 = sp (first argument), switch to stub_stack, align, call. */
__asm__(
    ".global _start\n"
    "_start:\n"
    "   mv a0, sp\n"
    "   la sp, stub_stack\n"
    "   li t0, " STR(STACK_SIZE) "\n"
    "   add sp, sp, t0\n"
    "   andi sp, sp, -16\n"
    "   call _start_c\n"
    "   unimp\n"
);
#endif
