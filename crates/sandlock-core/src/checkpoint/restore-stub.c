/*
 * restore-stub: freestanding self-restore stub (x86_64).
 *
 * This is a core component of the checkpoint restore engine, not a test
 * fixture: the supervisor execs this stub into a fresh, fully-sandboxed process
 * to reconstruct a checkpoint. It is compiled by build.rs into OUT_DIR and its
 * path is exposed to the crate via the RESTORE_STUB_PATH env var.
 *
 * Built with: cc -static -nostdlib -no-pie -O2 -o restore-stub restore-stub.c
 *
 * Reads a control blob (see checkpoint/restore_blob.rs) from CTRL_FD, maps the
 * checkpoint's anonymous regions, registers them with userfaultfd (missing
 * mode), hands the uffd to the supervisor at UFFD_SLOT, waits for the supervisor
 * to attach its pager (GO_FD), then rt_sigreturns into the checkpoint register
 * context. This first cut handles anonymous regions only: no vDSO relocation,
 * no file-backed regions, no fd table (those come later).
 *
 * Exit codes (all _exit): 2 blob read, 3 bad magic/version, 4 mmap region,
 * 5 userfaultfd, 6 UFFDIO_API, 7 UFFDIO_REGISTER, 8 dup2 uffd, 9 ready write,
 * 10 go read. rt_sigreturn does not return; if it does, exit 11.
 */
#define CTRL_FD 3
#define READY_FD 4
#define GO_FD 5
#define UFFD_SLOT 6

#define SYS_read 0
#define SYS_write 1
#define SYS_mmap 9
#define SYS_ioctl 16
#define SYS_dup2 33
#define SYS_exit 60
#define SYS_rt_sigreturn 15
#define SYS_userfaultfd 323
#define SYS_lseek 8
#define SYS_fstat 5

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x2
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10
#define O_CLOEXEC 02000000
#define O_NONBLOCK 04000
#define UFFD_USER_MODE_ONLY 1
#define SEEK_END 2
#define SEEK_SET 0

typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;

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
#define SC0(n) sc6(n,0,0,0,0,0,0)
#define SC1(n,a) sc6(n,(u64)(a),0,0,0,0,0)
#define SC2(n,a,b) sc6(n,(u64)(a),(u64)(b),0,0,0,0)
#define SC3(n,a,b,c) sc6(n,(u64)(a),(u64)(b),(u64)(c),0,0,0)
#define SC6(n,a,b,c,d,e,f) sc6(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),(u64)(f))

static void die(int code) { SC1(SYS_exit, code); for(;;){} }

/* userfaultfd ioctls (x86_64). */
#define UFFDIO_API      0xc018aa3fUL
#define UFFDIO_REGISTER 0xc020aa00UL
#define UFFD_API        0xAAUL
#define UFFDIO_REGISTER_MODE_MISSING 1UL
struct uffdio_api { u64 api, features, ioctls; };
struct uffdio_register { u64 start, len, mode, ioctls; };

/* Blob layout mirror (little-endian; we run on x86_64 LE so struct reads work). */
struct blob_header {
    u32 magic, version, n_regions, n_fds;
    u64 regs_off; u32 regs_len, _pad; u64 anon_data_off;
};
struct blob_region {
    u64 start, end; u32 prot; unsigned char src, _p0[3]; u64 file_off, data_off;
};
#define BLOB_MAGIC 0x534c5242u
#define BLOB_VERSION 1u
#define NO_DATA 0xFFFFFFFFFFFFFFFFUL

/* ---- x86_64 rt_sigreturn frame -------------------------------------------
 * rt_sigreturn reads the ucontext at rsp (kernel does frame = rsp - 8; uc is at
 * frame+8 = rsp). We build a ucontext, set rsp to &uc, and syscall rt_sigreturn.
 * mcontext gregs order (x86_64): see REG_* below.
 */
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

/* Captured user_regs_struct order (27 u64), matching capture::ptrace_getregs. */
enum { UR_R15=0,UR_R14,UR_R13,UR_R12,UR_RBP,UR_RBX,UR_R11,UR_R10,UR_R9,UR_R8,
       UR_RAX,UR_RCX,UR_RDX,UR_RSI,UR_RDI,UR_ORIG_RAX,UR_RIP,UR_CS,UR_EFLAGS,
       UR_RSP,UR_SS,UR_FS_BASE,UR_GS_BASE,UR_DS,UR_ES,UR_FS,UR_GS };

/* `used`: the only reference is the module-level asm `call _start_c`, which the
 * optimizer cannot see, so without this -O2 would eliminate the function. */
__attribute__((used, noinline))
static void _start_c(void) {
    /* 1. Size the blob via lseek, mmap it. */
    i64 sz = SC3(SYS_lseek, CTRL_FD, 0, SEEK_END);
    if (sz <= 0) die(2);
    SC3(SYS_lseek, CTRL_FD, 0, SEEK_SET);
    void *blob = (void*)SC6(SYS_mmap, 0, sz, PROT_READ, MAP_PRIVATE, CTRL_FD, 0);
    if ((i64)blob < 0) die(2);
    struct blob_header *h = (struct blob_header*)blob;
    if (h->magic != BLOB_MAGIC || h->version != BLOB_VERSION) die(3);

    struct blob_region *regs_tbl =
        (struct blob_region*)((char*)blob + sizeof(struct blob_header));
    unsigned char *anon = (unsigned char*)blob + h->anon_data_off;
    u64 *gp = (u64*)((char*)blob + h->regs_off);

    /* 2. Map each anon region MAP_FIXED with its captured prot. (For now all
     * regions are anon.) The prot must match the checkpoint: an executable region mapped
     * without PROT_EXEC would fault as a protection violation (SIGSEGV) on the
     * instruction fetch rather than a uffd missing-page fault the pager can
     * serve. r->prot already holds standard PROT_* bits (see restore_blob.rs). */
    for (u32 i = 0; i < h->n_regions; i++) {
        struct blob_region *r = &regs_tbl[i];
        u64 len = r->end - r->start;
        i64 p = SC6(SYS_mmap, r->start, len, r->prot,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if ((u64)p != r->start) die(4);
    }

    /* 3. userfaultfd + API + register anon regions (missing mode).
     * O_NONBLOCK is mandatory: the supervisor pager polls this fd, and poll()
     * on a *blocking* userfaultfd always reports POLLERR (never POLLIN), so the
     * pager would spin and never serve a page. Hosts with
     * vm.unprivileged_userfaultfd=0 reject the plain form; retry with
     * UFFD_USER_MODE_ONLY (user-mode faults only, sufficient here). */
    i64 uffd = SC1(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) uffd = SC1(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
    if (uffd < 0) die(5);
    struct uffdio_api api = { UFFD_API, 0, 0 };
    if (SC3(SYS_ioctl, uffd, UFFDIO_API, &api) < 0) die(6);
    for (u32 i = 0; i < h->n_regions; i++) {
        struct blob_region *r = &regs_tbl[i];
        if (r->data_off == NO_DATA) continue; /* file-backed: kernel-paged (handled later) */
        struct uffdio_register reg = {
            r->start, r->end - r->start, UFFDIO_REGISTER_MODE_MISSING, 0 };
        if (SC3(SYS_ioctl, uffd, UFFDIO_REGISTER, &reg) < 0) die(7);
    }
    (void)anon; /* pages are served by the supervisor pager, not memcpy'd here */

    /* 4. Expose uffd at the agreed slot; signal READY; wait for GO. */
    if (SC2(SYS_dup2, uffd, UFFD_SLOT) != UFFD_SLOT) die(8);
    u64 one = 1;
    if (SC3(SYS_write, READY_FD, &one, 8) != 8) die(9);
    u64 got = 0;
    if (SC3(SYS_read, GO_FD, &got, 8) != 8) die(10);

    /* 5. Build the rt_sigframe on our current stack and rt_sigreturn.
     * The frame must be readable when the kernel consumes it; our stub stack is
     * a plain (non-uffd) mapping, so it always is. */
    struct uctx uc;
    for (unsigned k = 0; k < sizeof(uc); k++) ((char*)&uc)[k] = 0;
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
    m->fpstate = 0; /* no FP restore yet */

    /* Set rsp = &uc, then syscall rt_sigreturn. */
    register u64 rax __asm__("rax") = SYS_rt_sigreturn;
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "syscall\n\t"
        :
        : "r"(&uc), "r"(rax)
        : "memory");
    die(11); /* rt_sigreturn must not return */
}

/* No libc: provide the ELF entry. Align the stack and call into C. */
__asm__(
    ".global _start\n"
    "_start:\n"
    "   xor %rbp, %rbp\n"
    "   and $-16, %rsp\n"
    "   call _start_c\n"
    "   hlt\n"
);
