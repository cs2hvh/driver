// nexus_drv.c — kernel-mode skeleton for early CS2 DLL injection.
//
// THIS ITERATION (D4-step-1) does NOT inject anything yet. It only:
//   1. Registers a process-creation callback
//   2. Registers an image-load callback
//   3. Logs (via DbgPrint) when cs2.exe is created and when kernel32.dll
//      loads inside it
//
// Purpose: prove the driver loads via kdmapper, the kernel callbacks fire
// correctly, and we get a clean "TARGET" log line on cs2.exe spawn before
// we add the (riskier) APC + shellcode injection in the next iteration.
//
// View DbgPrint output on the host with Sysinternals DebugView.exe (must
// be run as Administrator; turn on "Capture Kernel" in Capture menu).

#include <ntddk.h>
#include <wchar.h>

// ---- Config (will be settable via IOCTL in a later iteration) -----------
static const WCHAR* g_targetExe = L"cs2.exe";

// ---- Callbacks ----------------------------------------------------------

// Extracts the base filename from a "\Device\HarddiskVolume...\path\file.exe"
// style UNICODE_STRING. Returns pointer into the caller-owned buffer.
static const WCHAR* BaseName(PCUNICODE_STRING full) {
    if (!full || !full->Buffer || full->Length == 0) return NULL;
    USHORT len = full->Length / sizeof(WCHAR);
    const WCHAR* base = full->Buffer;
    for (USHORT i = 0; i < len; i++) {
        if (full->Buffer[i] == L'\\') base = &full->Buffer[i + 1];
    }
    return base;
}

VOID ProcessNotify(_In_ PEPROCESS Process,
                   _In_ HANDLE ProcessId,
                   _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (!CreateInfo) return;                  // exit notification — ignore
    if (!CreateInfo->ImageFileName) return;

    PCWSTR base = BaseName(CreateInfo->ImageFileName);
    if (!base) return;

    if (_wcsicmp(base, g_targetExe) == 0) {
        DbgPrint("[nexus_drv] TARGET process created: pid=%lu image=%wZ\n",
                 (ULONG)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName);
    }
}

VOID ImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName,
                     _In_ HANDLE ProcessId,
                     _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    if (!FullImageName) return;

    PCWSTR base = BaseName(FullImageName);
    if (!base) return;

    // Only log a small set of "milestone" DLLs so we don't spam DbgPrint
    // every load. kernel32.dll is the canonical "process ready for APC
    // injection" marker we'll use later.
    if (_wcsicmp(base, L"kernel32.dll") == 0 ||
        _wcsicmp(base, L"ntdll.dll")    == 0 ||
        _wcsicmp(base, L"cs2.exe")      == 0)
    {
        DbgPrint("[nexus_drv] image-load: %ls in pid=%lu base=%p size=0x%X\n",
                 base, (ULONG)(ULONG_PTR)ProcessId,
                 ImageInfo->ImageBase, (ULONG)ImageInfo->ImageSize);
    }
}

// ---- DriverEntry --------------------------------------------------------
//
// kdmapper-mapped drivers receive a fake DriverObject (or NULL). We don't
// use it. We just register the kernel callbacks and stay resident.
// Without a real DriverObject the system can't unload us — that's fine for
// our purposes; the user reboots to "uninstall".

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[nexus_drv] DriverEntry — registering callbacks\n");

    NTSTATUS s1 = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    DbgPrint("[nexus_drv] PsSetCreateProcessNotifyRoutineEx: 0x%08X\n", s1);

    NTSTATUS s2 = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    DbgPrint("[nexus_drv] PsSetLoadImageNotifyRoutine:       0x%08X\n", s2);

    if (!NT_SUCCESS(s1) || !NT_SUCCESS(s2)) {
        // Best-effort cleanup of whichever succeeded.
        if (NT_SUCCESS(s1)) PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
        if (NT_SUCCESS(s2)) PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
        return NT_SUCCESS(s1) ? s2 : s1;
    }

    DbgPrint("[nexus_drv] Ready — waiting for %ls\n", g_targetExe);
    return STATUS_SUCCESS;
}
