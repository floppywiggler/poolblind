/*
 * payload.c -- simple test driver
 *
 * Triggers Defender static signals: DbgPrint import, known string, "DriverEntry" symbol.
 * See payload_stealthy.c for the AV-clean version.
 * Verify execution with DebugView: ed Kd_DEFAULT_Mask 0xf
 */

#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[indpages-payload] DriverEntry reached - MmAllocateIndependentPagesEx mapped this driver.\n");
    DbgPrint("[indpages-payload] Pool scanners walking ExAllocatePool allocations will not find us.\n");

    return STATUS_SUCCESS;
}
