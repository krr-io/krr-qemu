# AGENTS.md — KRR QEMU

This tree is QEMU **7.0.0** extended into the userspace half of KRR (Kernel Record & Replay,
OSDI '25, https://www.usenix.org/system/files/osdi25-zhang-tianren.pdf). `README.md` is the
user guide (record/replay commands, gdb, reverse debugging, NVMe) — read it before changing
behaviour it documents, and update it when you do.

- **Record**: `-accel kvm` on the KRR host kernel. QEMU starts/stops recording through RR KVM
  ioctls, drains events from the shared ivshmem queue + KVM, and writes the trace files.
- **Replay**: `-accel tcg -kernel-replay <name> -singlestep`. Pure userspace; no KRR KVM needed.
  Events are injected at the instruction count / RIP where they were recorded.

KRR is a three-repo system. Sibling checkouts in `../`:

| Repo | Role |
| --- | --- |
| `../kernel-rr-linux` | Host KVM 5.17.5: RR ioctls, hypercalls, hypervisor-side event recording |
| `krr-qemu` (this) | Drives record, persists trace, replays on TCG |
| `../linux-6.1.0` | Guest kernel with the in-guest recorder agent |

## Where the KRR code is

`git diff 4232e7088 HEAD` shows everything on top of upstream 7.0.0.

- `kernel_rr/` — main KRR code (built via `kernel_rr/meson.build`, softmmu only):
  - `kernel_rr.c` — core: record session, reading the ivshmem queue, event list/trace file I/O,
    replay of each event type (`rr_do_replay_*`), breakpoint insertion at guest symbols, SMP
    lock-owner / inst-sync handling, stats.
  - `dma.c` — disk DMA record/replay (IDE, NVMe) → `kernel_rr_dma-<dev>.log`.
  - `network.c` — E1000 network data → `kernel_rr_network.log`.
  - `mem_log.c`, `verifier.c` — memory-access logs and replay state verification.
  - `replay_debugging.c` — periodic snapshots for gdb reverse debugging.
  - `krr_trace_helper.c` — standalone `krr-trace-helper` tool to search a trace by event type/id.
  - `generate_symbol.sh`, `rr_gen_replay_symbols.py` — guest symbol generator (see below).
  - `rr_guest_config` — sample guest kernel `.config`; `Support-for-KRR-guest-recorder-patch` — guest patch.
  - `*.py`, `*.sh` (`observer.py`, `all-test*.sh`, `send_qmp.py`, …) — paper experiment
    harness; has hard-coded paths/users, not general tooling.
- `include/sysemu/kernel-rr.h` — public KRR API used across QEMU + **generated guest symbol addresses**.
- `linux-headers/linux/kernel_rr.h`, `linux-headers/linux/kvm.h` — copies of the host RR ABI.
- Hooks elsewhere (keep them small, put logic in `kernel_rr/`):
  - `accel/kvm/kvm-all.c` — `KVM_START_RECORD`/`KVM_END_RECORD`, result buffer, exits.
  - `accel/tcg/cpu-exec.c`, `accel/tcg/translator.c`, `accel/tcg/tcg-accel-ops-mttcg.c`,
    `target/i386/tcg/*` (translate, seg/int/misc/excp helpers) — replay injection points
    (interrupts, exceptions, syscalls, rdtsc/rdseed, IO input, inst counting).
  - `hw/ide/core.c`, `hw/nvme/ctrl.c` (`rr-ignore` property), `hw/net/e1000.c`,
    `softmmu/dma-helpers.c`, `hw/intc/apic.c` — device-side record/replay.
  - `softmmu/vl.c`, `qemu-options.hx` — options `-kernel-replay`, `-krr-debug`, `-krr-trap`,
    `-krr-autostart`, `-replay-log-bound`, `-replay-log-inst`, `-snapshot-period`, `-restore-snapshot-id`.
  - `hmp-commands.hx`, `monitor/hmp-cmds.c`, `monitor/qmp-cmds.c` — `rr_record`/`rr-record`,
    `rr_end_record`/`rr-end-record`.
  - `gdbstub.c`, `migration/ram.c`, `softmmu/cpus.c` — gdb stop handling, snapshots.

Replay is meant to coexist with plain (non-KRR) TCG and KVM: gate new behaviour on
`rr_in_replay()` / `rr_in_record()` so regular QEMU use is unaffected.

## Guest symbols (important)

Replay traps guest kernel code at fixed addresses defined as macros in
`include/sysemu/kernel-rr.h` (`SYSCALL_ENTRY`, `RR_CFU_BEGIN`, `RR_GFU4`, …). They are
generated from the guest `vmlinux` and **must match the exact guest kernel being replayed**:

```bash
bash kernel_rr/generate_symbol.sh /abs/path/to/vmlinux /abs/path/to/krr-qemu
```

This rewrites the header in place and rebuilds `build/`. Consequences:
- Don't hand-edit the address values; rerun the script. Diffs in that block are expected
  whenever the guest kernel changes — don't commit them unless they belong to the change.
- `rr_gen_replay_symbols.py` resolves some points by **file:line** in the guest
  (`getuser.S:88/103/127/147/162`, `entry_64.S:226/702`, `rr_serialize.c:147`) and others by
  function name (`rr_cfu_begin`, `rr_gfu_begin`, `rr_handle_syscall`, …); the active set is the
  symbol dict near the end of the script. Renaming those guest functions or shifting those lines
  requires updating the script. Adding a new trap point = new `fetch_*` + dict entry + `#define` in the header.

## Cross-repo ABI — keep in sync

Duplicated by hand; a mismatch corrupts record silently:
1. Event structs / `EVENT_TYPE_*` / queue header: `linux-headers/linux/kernel_rr.h` ↔
   `../kernel-rr-linux/arch/x86/include/uapi/asm/kernel_rr.h` ↔ `../linux-6.1.0/arch/x86/include/asm/kernel_rr.h`.
   (QEMU's copy additionally has `EVENT_TYPE_MMIO` 13, `EVENT_TYPE_PTE` 14 and helper prototypes.)
2. RR ioctl numbers: `linux-headers/linux/kvm.h` ↔ `../kernel-rr-linux/include/uapi/linux/kvm.h`.
3. Hypercall numbers (`KVM_HC_RR_*` in `include/sysemu/kernel-rr.h`) ↔ host/guest `kvm_para.h`.
4. ivshmem layout (header, lock owner, per-vcpu inst count offsets) in `kernel_rr/kernel_rr.c`
   ↔ host `arch/x86/kvm/kernel_rr.c` ↔ guest `arch/x86/kernel/kvm_ivshmem.c`.

Note: `scripts/update-linux-headers.sh` would wipe the RR additions in `linux-headers/` — don't run it.

## Build

```bash
mkdir -p build && cd build
../configure --target-list=x86_64-softmmu
make -j$(nproc)
```

Only `x86_64-softmmu` is supported/tested. Outputs: `build/qemu-system-x86_64`,
`build/krr-trace-helper`. After changing `include/sysemu/kernel-rr.h`, a rebuild recompiles
most of the tree.

## Testing

No automated tests cover KRR; upstream `make check` only guards against breaking generic QEMU.
Verify behaviour end-to-end (commands in `README.md`):
1. Record on a KRR host: `-accel kvm -cpu host -no-hpet`, ivshmem device backed by
   `/dev/shm/ivshmem`, then `rr_record <name>` … `rr_end_record` in the monitor.
   Produces `<name>` (snapshot), `kernel_rr.log`, `kernel_rr_dma-*.log`, `kernel_rr_network.log`
   in the working directory (normally `build/`).
2. Replay with identical VM config except `-accel tcg -cpu Broadwell -kernel-replay <name> -singlestep`;
   `cont` to start (or `-krr-autostart`). Success = runs to the end and event stats match the record.
3. Debug: `-krr-debug` for verbose logs, `-D <file> -replay-log-bound start=N1,end=N2` for an
   instruction trace, `-S -s` + `gdb vmlinux` for gdb, `krr-trace-helper` to inspect the trace.

Recording needs the KRR KVM loaded on the host and several GB of RAM (`-m` + ivshmem size);
ask before starting long-running or memory-heavy VMs. Supported devices: IDE, NVMe, E1000
(virtio not supported). Intel hosts only.

## Conventions

- QEMU coding style (`docs/devel/style.rst`): 4-space indent, no tabs, braces on all blocks;
  `scripts/checkpatch.pl` is available for new code. Match the surrounding KRR code otherwise.
- KRR symbols are prefixed `rr_` / `krr_`; new options use the `krr-` prefix.
- Use `LOG_MSG(...)` (from `include/sysemu/kernel-rr.h`, gated by `rr_debug_enabled` / `-krr-debug`) instead of unconditional
  `printf` on hot replay paths; replay executes per instruction (`-singlestep`).
- Commit messages: short imperative English subject, no subsystem prefix
  (e.g. "Add option for replay autostart").
