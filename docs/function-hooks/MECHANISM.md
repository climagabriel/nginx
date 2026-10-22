# How a config hook would actually execute

The question this answers: with the config-driven design (strategy C in
`README.md`), **does the running binary modify its own machine code at
runtime?** Yes. The nginx master process rewrites the first bytes of the
target function, in its own `.text` segment, during config load. Everything
below is the concrete mechanism, and `selfpatch.c` in this directory is a
~90-line working proof of it that compiles and runs with no nginx involved.

## The five moving parts

**1. The target's arguments are already in registers.** On the x86-64 System V
ABI, when `ngx_http_file_cache_aio_open(r, c)` is entered, `r` is in `%rdi` and
`c` is in `%rsi`. So "acting on the input arguments" costs nothing to arrange:
at the first instruction they are sitting in known registers. The hook just has
to run before those registers are disturbed.

**2. Reserved NOP space at build time.** Patching the first real instructions
would mean disassembling and relocating them (a displaced relative jump or
RIP-relative access has to be fixed up). The clean way, which the Linux kernel's
ftrace and livepatch use, is to build with `-fpatchable-function-entry=N`: gcc
emits N NOP bytes at every function's entry. There is nothing to relocate
because you only ever overwrite NOPs. The PoC's `target()` compiles to:

```
target:
  f3 0f 1e fa   endbr64          <- CET landing pad (see caveat 5)
  90 90 90 ...  nop x15          <- reserved patch space
  ... real prologue ...
```

**3. The runtime self-modification.** To install the hook the process:
- `mprotect()`s its own code page to `READ|WRITE|EXEC`,
- overwrites 5 NOP bytes with `E9 <rel32>`, a near jump to a trampoline,
- `mprotect()`s the page back to `READ|EXEC` and flushes the i-cache.

This is the self-modifying step. The on-disk binary is never touched; only the
in-memory image changes. (In the PoC, `objdump` of the file still shows NOPs
after a successful run, because the bytes that changed are in RAM.)

**4. The trampoline restores correctness.** The jump lands on a small stub that
must leave the original function able to run. It:
- saves the caller-saved registers (the arg regs `%rdi`/`%rsi` among them),
- 16-byte-aligns the stack and `call`s the compiled hook, which reads `r`/`c`
  from `%rdi`/`%rsi`,
- restores the registers,
- jumps back into the target *past the 5 bytes it overwrote*, into the
  remaining NOPs, which slide into the real prologue.

Control flow end to end:

```
caller --(call)--> target entry (now: jmp) --> trampoline
                                                  save arg regs
                                                  call hook(r, c)   <- user's C body
                                                  restore arg regs
                                                  jmp target+N       <- real prologue
                                               --> original function runs, returns
```

The hook runs, then the function proceeds as normal: exactly the config
example. Because the hook sees the real `r` and `c` pointers, anything it writes
through them is visible to the original function (that is how an entry hook
would mutate behaviour). Skipping or replacing the original is a harder variant
and is out of scope.

**5. Where the hook code comes from.** The config block's C body is wrapped in a
generated function with the target's real prototype, compiled at config load
with `cc -shared -fPIC` against the nginx headers, and `dlopen`/`dlsym`'d to get
the address the trampoline calls. A compile error fails `nginx -t`, not the
running server. This is why strategy C needs a **compiler and the headers on
every edge** — one of the reasons it does not survive production review.

## When, and in which process

The master applies every patch during config load, **before it forks workers**.
`fork()` copies the already-patched address space, so each worker inherits the
hook with no per-worker patching and no cross-process code writes. The cost is
that each patched page stops being shared and becomes a private, dirtied
copy-on-write page per worker (a few KB per hook: negligible). On `reload`
(SIGHUP) the master re-reads config, re-patches, and forks fresh workers; a
live worker's running code is never rewritten under it.

## Why hardened production fights this (the real blocker)

The proof-of-concept runs, but each of these is a production edge's default
posture, and each breaks the technique:

- **W^X / `mprotect` on `.text`.** Making executable code writable, even
  briefly, is exactly what hardening forbids. SELinux `execmem`, a
  `PROT_EXEC`-restricting seccomp policy, or hardened kernels can deny the
  `mprotect` outright.
- **CET Indirect Branch Tracking.** The `endbr64` at each function entry is the
  mandatory landing pad for indirect calls. The PoC had to patch *after* the
  `endbr64` to preserve it; on an IBT-enforcing CPU the trampoline and the
  resume point each need their own `endbr64` or the indirect branch faults
  with `#CP`. The first PoC version overwrote the pad and only survived because
  this host does not enforce IBT.
- **A compiler on the edge.** Strategy C ships `cc` and the nginx headers to
  production and runs codegen from a config file. That is a remote-code-
  execution surface by design.
- **Multi-worker timing and re-entrancy.** A hook on a hot, re-entrant function
  (anything touching `r->main`, timers, or the event loop) can corrupt request
  state the same way a bad filter module does, with no module boundary to
  contain it.

## The versions that never self-modify

- **`-finstrument-functions`** bakes a `__cyg_profile_func_enter` call into
  every function at build time: no runtime patching, but no typed arguments
  (only the function address) and a call on every function.
- **Source-generated trampolines** rename `foo` to `foo__real` at build time
  and emit a wrapper `foo` that calls the hook then `foo__real`: typed
  arguments, the linker wires it, the binary never rewrites itself; the hook set
  is fixed at build, not config.

Both get the hook effect through the compiler and linker instead of runtime
self-modification, which is why they are the cheaper and reviewable paths.

## Running the proof

```
gcc -O0 -fcf-protection=full -fpatchable-function-entry=16 -no-pie -o selfpatch selfpatch.c
./selfpatch
```

Observed on x86-64, gcc 11.4:

```
before patch:  target(3,4)   = 7
patching target() entry -> trampoline -> hook -> original...
    [hook fired]  saw args a=10 b=20
after  patch:  target(10,20) = 30
    [hook fired]  saw args a=7 b=8
after  patch:  target(7,8)   = 15
```

Before the patch the hook is silent. After the process overwrites `target`'s
entry in its own memory, every call diverts through the trampoline, the hook
reads the live arguments, and the original function still returns the right
value. That is the whole mechanism, in miniature.
