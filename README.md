# poolblind

BYOVD kernel mapper built on `MmAllocateIndependentPagesEx`. Loads an unsigned driver
without leaving a pool entry.

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

## How it works

Kernel R/W comes from Intel's NAL driver (`iqvw64e.sys`, v1.3.1.0) via IOCTL `0x80862007`.
Three cases: memcopy, VA-to-PA translation, `MmMapIoSpace`/`MmUnmapIoSpace` wrappers.
That's enough to build the rest.

1. Find `ntoskrnl.exe` base via `NtQuerySystemInformation(11)`
2. Walk the kernel export directory over the R/W primitive to resolve target functions
3. Call kernel functions by patching the first 12 bytes of `NtAddAtom` with
   `mov rax, target; jmp rax`, issuing the syscall from user mode, then restoring immediately
4. Allocate a PFN-backed region, PE-load the image, fix relocations, resolve imports,
   apply per-section page protections, call the entry point
5. Free with `MmFreeIndependentPages`

`MmFreeIndependentPages` isn't exported. The mapper finds it by pattern scan over the
`PAGE` section, falling back to a binary search over `.pdata` if the pattern misses on the
running build. Alloc and free share a translation unit, so their entries are adjacent in the
exception directory. O(log N) point reads to find it.

---

## Build

VS 2022, WDK 10.0.26100.0. Run from an x64 Native Tools Command Prompt for VS 2022:

```
build.bat
```

Produces `mapper/mapper.exe`, `payload/payload.sys`, `payload/payload_stealthy.sys`.

---

## Run

1. Get `iqvw64e.sys` v1.3.1.0 — it's on [loldrivers.io](https://www.loldrivers.io/).
   Drop it in `mapper/`.
2. Enable test signing or use your own method to allow unsigned drivers. The NAL driver is
   signed. The payload isn't.
3. `mapper\mapper.exe` as Administrator.
4. Default payload: `payload.sys`. Stealthy variant:
   `copy mapper\payload_stealthy.sys mapper\payload.sys` then run again.

---

## Payloads

**payload.sys** — imports `DbgPrint`, logs two lines from `DriverEntry`. Verify with
DebugView or WinDbg (`ed Kd_DEFAULT_Mask 0xf` to enable kernel output). Windows Defender
flags this file on disk through static analysis: known string in `.rdata`, `DbgPrint` in
the import table, `DriverEntry` in the PDB symbol path. Useful for confirming the mapper
works before worrying about evasion.

**payload_stealthy.sys** — no includes, no imports, no string literals, entry point renamed
to `PocEntry`. The entire `.text` section compiles to six bytes:
`mov eax, 0x600DC0DE; ret`. The mapper confirms execution by checking the return value —
no DebugView, no shared memory, no side channel. Passes Defender static scan.

---

## Verification

During Part 1, run `poolmon.exe /b /iCamp`. The `Camp` tag appears with one allocation.
After the pool free, it's gone.

During Part 2, `Camp` never appears. Open System Informer → Memory → Pool Allocations,
filter by `Camp`. Same result in a GUI. The pool scanner sees 36,283 entries whether or not
the mapped driver is executing.

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

Windows 11 24H2 (ntoskrnl build 26100.x). `MmFreeIndependentPages` is not exported and its
location is build-specific — the runtime output shows the resolved address.

---

## What it doesn't cover

**No DSE bypass.** Unsigned drivers won't load unless DSE is already off. Test signing mode
(`bcdedit /set testsigning on`) is the easy option for a lab. If you want to disable DSE at
runtime, that's a separate BYOVD operation targeting `g_CiEnabled` or `CiInitialize`.

**No HVCI support.** The `MmMapIoSpace` remap trick used to write to read-only kernel pages
doesn't survive Virtualization Based Security. If HVCI is on, the write primitive fails.

**Detection surface.** The remaining exposure is the NAL driver load: SCM service
registration, the physical memory IOCTLs it responds to. That's not a payload problem — the
binary that lands in kernel memory is clean. The driver that puts it there isn't.
