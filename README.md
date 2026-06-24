# poolblind

A clean implementation of pool-invisible kernel page allocation using
`MmAllocateIndependentPagesEx`, demonstrated via BYOVD.

The standard approach — `ExAllocatePool2`, which is what kdmapper uses — registers every
allocation in pool accounting. Anything at or above one page appears in
`SystemBigPoolInformation` (class 66), queryable by any unprivileged user-mode process.
Anti-cheat engines poll this list constantly looking for unknown tags. The `Camp` tag
kdmapper leaves behind has been a detection for years. Check for it yourself:
`poolmon.exe /iCamp`.

`MmAllocateIndependentPagesEx` skips the pool layer and commits physical pages directly
from the PFN database. No pool headers, no big-pool registration. The mapped driver runs
in kernel memory and `NtQuerySystemInformation(66)` returns nothing related to it.

Full writeup: [dkom.dev/posts/byovd-indpages](https://dkom.dev/posts/byovd-indpages/)

---

## What this is (and isn't)

This is a **technique demonstration**, not a finished tool. The point is
`MmAllocateIndependentPagesEx` — the pool-invisible allocation primitive. Everything
wrapped around it (the BYOVD driver, the NtAddAtom call gate, the toy payloads) exists
to show the technique working in isolation so you can understand it and integrate the
relevant parts into whatever you're building.

This is not a kdmapper replacement. It is not a complete cheat loader or implant
framework. It's one layer — specifically the memory allocation layer — that you'd slot
into a larger chain. Something like:

- **Game cheat / trainer**: you already have a kernel R/W primitive from your own BYOVD
  driver. Replace the NAL IOCTL layer here with your primitive, drop in your actual cheat
  code as the payload, and the pool scanner stops finding your allocation.
- **EDR bypass / implant**: same idea. You need kernel code execution that doesn't show
  up in pool monitors or memory integrity scans. This handles the allocation. You bring
  the primitive and the payload.
- **Research**: you want to understand how independent page allocation works and verify
  it's actually invisible to common scanners. Build, run, check PoolMon, done.

---

## On the Intel NAL driver

`iqvw64e.sys` (Intel Network Adapter Diagnostic, v1.3.1.0) is used here because it's
well-documented, the IOCTLs are publicly understood, and it makes the demo easy to
reproduce. It is also on every anti-cheat and EDR blacklist in existence. Using it in
production is roughly equivalent to writing your payload in Comic Sans.

The NAL driver is interchangeable. Any BYOVD driver that gives you kernel memory read,
write, and physical mapping covers what this mapper needs. Hundreds of vulnerable signed
drivers exist — [loldrivers.io](https://www.loldrivers.io/) has the list. Pick one that
isn't already burned, wrap the three IOCTLs (`nal_read`, `nal_write`, `nal_map_io`) for
your driver's interface, and the rest of the code doesn't change.

If you already have kernel code execution through some other means — a different BYOVD
primitive, a driver you signed yourself, a hypervisor — you don't need the BYOVD layer
at all. Just call `MmAllocateIndependentPagesEx` directly.

---

## How it works

The kernel R/W primitive (whatever driver you use) enables:

1. Find `ntoskrnl.exe` base via `NtQuerySystemInformation(11)`
2. Walk the kernel export directory to resolve target functions
3. Call kernel functions via NtAddAtom patch: overwrite 12 bytes with
   `mov rax, target; jmp rax`, syscall from user mode, restore immediately
4. Allocate a PFN-backed region, PE-load the image, fix relocations, resolve imports,
   apply per-section page protections, call the entry point
5. Free with `MmFreeIndependentPages`

`MmFreeIndependentPages` isn't in the export table. The mapper finds it by pattern scan
over the `PAGE` section, falling back to a binary search over `.pdata` if the pattern
misses on the running build. Alloc and free share a translation unit, so their entries
are adjacent in the exception directory — O(log N) point reads to locate it.

---

## Build

VS 2022, WDK 10.0.26100.0. Run from an x64 Native Tools Command Prompt for VS 2022:

```
build.bat
```

Produces `mapper/mapper.exe`, `payload/payload.sys`, `payload/payload_stealthy.sys`.

---

## Run

1. Get `iqvw64e.sys` v1.3.1.0 from [loldrivers.io](https://www.loldrivers.io/).
   Drop it in `mapper/`.
2. `mapper\mapper.exe` as Administrator.
3. Default payload: `payload.sys`. Stealthy variant:
   `copy mapper\payload_stealthy.sys mapper\payload.sys` then re-run.

No test signing required. The NAL driver is legitimately signed and loads normally.
The payload is never presented to the kernel loader — it is mapped directly into memory
pages via `MmAllocateIndependentPagesEx`. CI validation only fires on the `NtLoadDriver`
path; this technique bypasses that path entirely.

---

## Payloads

The two payloads here are proof-of-execution only. Replace them with your own code.

**payload.sys** — imports `DbgPrint`, logs two lines from `DriverEntry`. Verify with
DebugView or WinDbg (`ed Kd_DEFAULT_Mask 0xf`). Defender flags this on disk through
static analysis alone: known string in `.rdata`, `DbgPrint` in the import table,
`DriverEntry` in the PDB path. Useful for confirming the mapper works before thinking
about evasion.

**payload_stealthy.sys** — no includes, no imports, no strings, entry point renamed
to `PocEntry`. The `.text` section is six bytes: `mov eax, 0x600DC0DE; ret`. Execution
confirmed by checking the return value in user mode — no DebugView, no side channel.
Passes Defender static scan. Closer to what a real payload would look like structurally:
position-independent, no import table, no recognisable symbols.

---

## Verification

During Part 1, run `poolmon.exe /b /iCamp`. The `Camp` tag appears with one allocation.
After the pool free, it's gone.

During Part 2, `Camp` never appears. Open System Informer → Memory → Pool Allocations,
filter by `Camp`. The pool scanner sees 36,283 entries whether or not the mapped driver
is executing.

```
=== Part 1: ExAllocatePool2 (pool-visible) ===

  -> ExAllocatePool2 (24576 bytes)
  -> base: 0xffff808ebe9f2000
  BigPoolInformation: 36284 entries
  [FOUND]  0xffff808ebe9f2000  size=0x6000  tag='Camp'
[+] ExAllocatePool2 allocation IS in BigPool

=== Part 2: MmAllocateIndependentPagesEx (pool-invisible) ===

  -> MmAllocateIndependentPagesEx (24576 bytes)
  -> base: 0xffffe581ff598000
  BigPoolInformation: 36283 entries
  [NOT FOUND]  0xffffe581ff598000
[+] MmAllocateIndependentPagesEx allocation NOT in BigPool (expected)

[*] freeing independent pages...
[+] freed
```

---

## Tested on

Windows 11 24H2 (ntoskrnl build 26100.x). `MmFreeIndependentPages` is not exported and
its location is build-specific — the runtime output shows the resolved address.

---

## What's missing

**DSE bypass — but not for the payload.** DSE is not relevant to this technique. The
payload never goes through `NtLoadDriver` or SCM, so CI never validates it. If you want
to load a driver the conventional way (via SCM, with a device object and a proper
`DriverEntry`), you need DSE disabled separately. That is a different technique for a
different use case — it is not a missing piece of this one.

**HVCI.** The `MmMapIoSpace` remap trick used to write to read-only kernel pages doesn't
survive Virtualization Based Security. If HVCI is on, the write primitive breaks.

**Driver load detection.** The pool entry is gone, but the BYOVD driver load still
leaves traces: SCM service registration, the physical memory IOCTLs it responds to.
That's a separate layer. This project handles what happens after you already have kernel
access.
