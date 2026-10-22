# nginx function hooks: feasibility and token-cost estimate

**What is being estimated.** A config-driven mechanism to attach native C
code to the entry and/or exit of a named nginx C function, with access to
that function's arguments, after which the original function runs normally.
The requested config shape:

```
ngx_http_file_cache_aio_open {
    # C body with the function's typed arguments in scope: r, c
    # runs, then the real ngx_http_file_cache_aio_open proceeds
}
```

**Naming.** This is not BPF. BPF is sandboxed bytecode verified and run by
the kernel on attach points. What is described here is userspace function
interception with native, unsandboxed C compiled from the config: closer to
SystemTap guru mode, DTrace `fbt` with a C actor, or a Frida Interceptor.
The document calls them *hooks* and the subsystem *ngx_hooks*.

---

## 1. Why this is hard in nginx specifically

The toy example hides four problems, each a subproject.

**1a. The targets are `static`.** `ngx_http_file_cache_aio_open` is a
file-local function (`nm` shows it as `t`, not `T`). It has no entry in the
dynamic symbol table, so `dlsym` cannot find it and `-Wl,-E` (which nginx
already passes) does not export it. Resolving a hook target by name means
either parsing DWARF from an unstripped binary or building a name->address
map at compile time from a custom pass. Vanilla ships stripped; nginx-gcdn
edges keep DWARF, but the fork does not promise it.

**1b. The compiler inlines the interesting functions.** The release binary
carries 462 `.constprop`/`.isra`/`.part`/`.cold` clones. A function that is
fully inlined into its caller has no prologue to patch and no single address
to name. The set of hookable functions is therefore *not* "every function in
the source" but "every function the optimizer left standalone at this -O2
build", which changes build to build. Any honest design must enumerate the
actually-hookable set from the built object files, not from source.

**1c. Argument typing.** "acting on the input arguments" means the hook body
must see `ngx_http_request_t *r` and `ngx_http_cache_t *c` with their real
types. That prototype is not in the binary. The generator must pull each
target's signature from a source index (DWARF, or a pre-built prototype
table generated from the headers) and emit a shim with the matching
signature, or the body will not compile.

**1d. nginx is pre-fork and event-driven.** Patching must happen in the
master before `fork()` so every worker inherits it; patching a live worker
means cross-process code modification and W^X page remapping per worker.
A hook that blocks or re-enters the event loop (most interesting functions
touch `r->main`, timers, or the connection) can corrupt request state the
same way a bad filter module does.

---

## 2. Three implementation strategies, by cost

| Strategy | Mechanism | Buys you | Costs you |
|---|---|---|---|
| A. Compile-time instrumentation | Build nginx with `-finstrument-functions`; `__cyg_profile_func_enter/exit` dispatches to hooks by address | No live patching; stable | Rebuild to change hooks; **no typed args** (only the raw frame); every function pays the call overhead; defeats inlining globally |
| B. Source-generated trampolines | A build pass wraps selected functions: `foo` becomes `foo__real`, `foo` calls the hook then `foo__real` | Typed args; no runtime patching; per-function opt-in | A compiler/codegen pass over the tree; the hook set is fixed at build, not config; large new build machinery |
| C. Config-load native compile + live patch | At config load, generate a `.so` from the snippet with the target's real prototype, `dlopen`, then rewrite the target's prologue to a trampoline into it | Matches the requested config exactly: hooks chosen in `nginx.conf`, typed args, no rebuild | A compiler on every edge, runtime codegen, arch-specific prologue patching, W^X, ptrace-free self-modification, security surface. The genuinely hard one. |

Strategy C is what the config example implies. Strategies A and B are the
cheaper ways to get 80% of the value; most of the estimate below is for a
*prototype of C limited to non-inlined, DWARF-named functions*, because that
is the smallest thing that satisfies the stated interface.

---

## 3. Minimum credible prototype (scope that was estimated)

- A `hooks { ... }` main-level block directive and a per-target nested block,
  parsed through `ngx_conf_read_token` / `NGX_CONF_BLOCK_START`.
- A build-time prototype table: a generator that reads the configured-tree
  headers and emits `target name -> C signature` for every non-static-inlined
  function, so the snippet compiles against real types.
- Entry hooks only (exit hooks and return-value capture deferred).
- x86-64 only, prologue-patch via a 5-byte relative jump to a generated
  trampoline, patched in the master before fork, under a mutex, with the
  original bytes saved for `nginx -s reload` restoration.
- A worker-local toggle so a hook can be disabled without a full reload.
- `cc` invoked at config load against the shipped nginx headers; failure
  fails the config load, not the running server.
- A `prove` test that fails against an un-hooked vanilla binary and passes
  with the hook, plus a crash-safety test that a re-entrant hook is rejected.

Explicitly **out** of the prototype: exit hooks, inlined targets, non-x86,
hooking functions that are themselves on the hot path, and any sandboxing of
the snippet (it runs with full worker privileges by construction).

---

## 4. Token-cost estimate

Calibration is from local Claude Code transcripts of this fork's and
nginx-gcdn's feature work. A single focused feature session on this codebase
runs **tens of millions of tokens**; the larger single-feature sessions land
at **70M-150M tokens** each, dominated by cache reads over long edit-compile
loops, not by fresh input. This feature touches config parsing, a new build
pass, codegen, arch-specific patching and a test harness: several such
sessions, plus adversarial review and a coredump round-trip when the prologue
patch is first wrong (it will be).

| Phase | What it is | Est. tokens |
|---|---|---|
| Exploration + design lock | DWARF/symbol survey, pick strategy, enumerate hookable set | 40-70M |
| Config + parser plumbing | the `hooks {}` block, lifecycle, reload restore | 30-50M |
| Prototype table generator | headers -> signatures build pass | 40-70M |
| Trampoline + patch core | codegen, 5-byte jump, W^X, pre-fork patching | 80-150M |
| Tests + flakiness loop + crash round-trips | prove tests, the first SEGV via coredump-analyst | 60-120M |
| Adversarial review + fixes | event/re-entry/pool-lifetime review, two iterations | 40-80M |

**Prototype total (strategy C, x86-64, entry-only): ~300-540M tokens**,
most likely around **380M**, spread over 4-7 sessions. The spread is wide
because the patch core is the kind of work that is either right in two
sessions or wrong in six.

**Cheaper variants.** Strategy A (instrument-functions, no typed args,
rebuild-to-change) is roughly **80-140M**: it is a configure flag, a dispatch
table and tests, with no codegen and no patching. Strategy B (source-generated
trampolines, typed args, build-time hook set) is roughly **150-260M**: real
codegen but no runtime patching and no W^X.

**Production hardening** beyond the prototype (exit hooks, inlined-target
story, multi-arch, snippet resource limits, making it safe to ship to edges)
is not costed here and is comparable again to the prototype itself.

---

## 5. Recommendation

If the goal is "observe/modify at a named function with config, no rebuild",
and the honest constraint is accepted that only non-inlined functions are
reachable, the minimum path is strategy C above at ~380M tokens for a
prototype. If a rebuild to change the hook set is acceptable, strategy B gives
the same typed-argument ergonomics for less than half the tokens and none of
the live-patching risk, and is the recommended first build. Strategy A is the
cheapest proof the plumbing works but its lack of typed arguments fails the
stated interface.

Every behavioral claim here about inlining, static linkage and `-Wl,-E` is
from the built 1.30.2-31 edge binary and this tree's `auto/cc/conf`; the
patch-safety claims are design assertions, not yet demonstrated by a running
config, and must be proven with a demo before any of this is asserted as fact.

---

## 6. Total dollar cost

"Total cost" has three lines. Only one is large, and it is not the AI.

**6a. AI / token spend is negligible.** The ~380M-token prototype estimate
sounds large but prices tiny, because long edit-compile sessions are dominated
by prompt-cache reads, which are an order of magnitude cheaper than fresh
input. Measured from local transcripts of feature-shaped sessions on this
exact codebase, one session costs:

| Model tier | $/session (median) |
|---|---|
| Opus 4.8 ($5/$25 per MTok) | ~$110 |
| Fable 5.1 ($10/$50) | ~$110 |
| Opus 5.5 ($4/$20) | ~$59 |
| Sonnet 5.5 ($2/$10) | ~$45 |

At 4-7 sessions, the prototype's entire model spend is **~$450-$1,500**, even
on the top tier. Call it **under $2,000** including the false starts the patch
core will cause.

**6b. Engineering time is the whole bill.** Strategy C is senior systems work:
runtime codegen, prologue patching, W^X, pre-fork safety, and a long crash-
debug tail. With AI assistance, a realistic prototype schedule for one senior
engineer:

| Phase | Calendar |
|---|---|
| Design + symbol/DWARF survey | 1-2 weeks |
| Config + parser plumbing | ~1 week |
| Prototype-table generator | 1-2 weeks |
| Trampoline + patch core (the crash tail) | 3-6 weeks |
| Tests, flakiness loop, coredump round-trips | 2-3 weeks |
| Adversarial review + two fix iterations | 1-2 weeks |

That is **~9-16 weeks**, roughly **2.5-4 months** of one senior engineer, plus
review time from one or two others. Assuming a fully loaded senior-engineer
cost of **~$12-15k/month** (salary, overhead, benefits; stated as an
assumption, not Gcore's actual figure), the engineering line is
**~$30k-60k**, and reviewers/SRE add perhaps **$10k-20k** of other people's
time.

**6c. Deploy and test infra is mostly sunk.** CI runs through the existing
builder container, loadtest/QAA runs through existing boxes, and the edge
fleet already exists. The incremental dollar cost of building, CI-ing and
canary-deploying is compute already paid for: hundreds of dollars of machine
time at most, not a capital line.

### Headline

| Line | Prototype cost |
|---|---|
| AI / token spend | ~$0.5k-2k (negligible) |
| Engineering (one senior, 2.5-4 mo) | ~$30k-60k |
| Review / SRE overhead | ~$10k-20k |
| Deploy + test infra (incremental) | ~$0.1k-0.5k |
| **Total, prototype** | **~$45k-80k** |

The number is a salary number, not a compute number: **~$45k-80k for a
strategy-C prototype**, dominated entirely by senior engineering months.

**Production is a different and larger question.** Hardening to ship to the
edge fleet (exit hooks, inlined-target story, multi-arch, snippet resource
limits) is comparable again, roughly doubling the engineering line. More to the
point, the feature compiles and runs **unsandboxed native C from nginx.conf on
every production edge**, so the binding constraint is not budget but security
review, which this design is unlikely to pass in strategy C's form. If the
goal is the typed-argument hook ergonomics, strategy B (build-time trampolines,
no runtime compiler on the edge) reaches a shippable design for roughly half
the engineering and a security review it can actually clear, and is the
recommended target if this is funded at all.

> **Mechanism detail:** `MECHANISM.md` in this directory walks through the
> runtime self-modification step by step, with a working ~90-line proof
> (`selfpatch.c`) that patches its own `.text` to hook a function.
