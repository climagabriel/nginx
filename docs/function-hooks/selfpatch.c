/*
 * Minimal proof that a running x86-64 binary can hook one of its own
 * functions by overwriting that function's first bytes at runtime.
 *
 * This is the core mechanism behind "nginx function hooks" strategy C,
 * reduced to ~80 lines with no nginx and no runtime compiler. It models
 * the config example: a hook body runs on the function's arguments, then
 * the original function proceeds as normal.
 *
 * Built with -fpatchable-function-entry=16, which tells gcc to emit 16
 * NOP bytes at the very start of target(). We overwrite 5 of those NOPs
 * with a jump; because they are NOPs, we never have to relocate any real
 * instruction (the clean technique the kernel's ftrace/livepatch use).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* The "nginx" function we want to hook. Two args, like (r, c).
   16 NOP bytes are reserved at entry by the build flag below. */
__attribute__((noinline, aligned(64)))
int target(int a, int b) {
    return a + b;                 /* the real work */
}

/* The user's hook body, as if generated from the config block.
   Same arg registers as target, so it sees a and b. */
void hook(int a, int b) {
    printf("    [hook fired]  saw args a=%d b=%d\n", a, b);
}

/* Where to resume the original function after the hook: target + 5,
   i.e. just past the 5 bytes we overwrote. Set at runtime. */
void *g_resume;

/* The trampoline the patched jump lands on: preserve the arg regs,
   call the hook, restore them, then jump back into target to run the
   real function. Hand-written so register/stack discipline is exact. */
__asm__(
".text\n"
".globl trampoline\n"
"trampoline:\n"
"    endbr64\n"
"    pushq %rdi\n"                /* save a (edi) and b (esi) */
"    pushq %rsi\n"
"    subq  $8, %rsp\n"           /* 16-byte align before the call */
"    call  hook\n"               /* hook(a,b): reads edi/esi */
"    addq  $8, %rsp\n"
"    popq  %rsi\n"               /* restore b */
"    popq  %rdi\n"               /* restore a */
"    jmp   *g_resume(%rip)\n"    /* continue the original function */
);
extern void trampoline(void);

static void patch_entry(void *fn, void *tramp) {
    long pg = sysconf(_SC_PAGESIZE);
    unsigned char *p = (unsigned char *)fn;
    /* CET: if the function opens with endbr64 (f3 0f 1e fa), that is the
       landing pad every indirect call to it must hit. Patch AFTER it so
       the pad survives; overwriting it faults on IBT-enforcing CPUs. */
    int off = (p[0]==0xf3 && p[1]==0x0f && p[2]==0x1e && p[3]==0xfa) ? 4 : 0;
    void *page = (void *)((uintptr_t)(p+off) & ~(uintptr_t)(pg - 1));
    if (mprotect(page, pg * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect(rwx)"); return;
    }
    int32_t rel = (int32_t)((intptr_t)tramp - ((intptr_t)(p+off) + 5));
    p[off] = 0xE9;                              /* near jmp rel32 */
    memcpy(p + off + 1, &rel, 4);
    mprotect(page, pg * 2, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)(p+off), (char *)(p+off) + 5);
    g_resume = (char *)fn + off + 5;            /* resume past the jump */
}

int main(void) {
    int (*call)(int, int) = target;           /* call through a pointer */

    printf("before patch:  target(3,4)   = %d\n", call(3, 4));

    printf("patching target() entry -> trampoline -> hook -> original...\n");
    patch_entry((void *)target, (void *)trampoline);

    printf("after  patch:  target(10,20) = %d\n", call(10, 20));
    printf("after  patch:  target(7,8)   = %d\n", call(7, 8));
    return 0;
}
