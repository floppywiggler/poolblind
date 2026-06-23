/*
 * payload_stealthy.c -- AV-evasive kernel proof-of-execution
 *
 * Eliminates the three Defender static signals from payload.c:
 *   - no string literals  (.rdata has nothing matchable)
 *   - no imports          (zero-entry import directory, no DbgPrint)
 *   - renamed entry point (PocEntry; "DriverEntry" never appears)
 *
 * Returns EXEC_MAGIC (0x600DC0DE) in EAX. Compile with /ENTRY:PocEntry /NODEFAULTLIB.
 * Mapper confirms execution via the return value -- no DebugView needed.
 */

#define EXEC_MAGIC 0x600DC0DE

__declspec(noinline)
long __stdcall PocEntry(void *driver_object, void *reg_path)
{
    (void)driver_object;
    (void)reg_path;
    return (long)EXEC_MAGIC;
}
