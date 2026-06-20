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

// ---- Code Integrity bypass --------------------------------------------
// Kdmapper-loaded drivers fail the "is this driver signed?" check that
// PsSetCreateProcessNotifyRoutineEx (and friends) perform. They return
// STATUS_ACCESS_DENIED (0xC0000022). To work around this, locate the
// kernel-internal g_CiOptions global and zero it out for the duration of
// our protected calls, then restore.
//
// g_CiOptions lives inside CI.dll (mapped into the kernel). We resolve it
// by scanning the bytes after CiInitialize.

static PVOID FindCiOptions(void) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"CiInitialize");
    PVOID ciInit = MmGetSystemRoutineAddress(&name);
    if (!ciInit) return NULL;

    // Scan up to 0x100 bytes for the lea referencing g_CiOptions.
    // Pattern: 4C 8D 35 ?? ?? ?? ??  (lea r14, g_CiOptions)
    PUCHAR p = (PUCHAR)ciInit;
    for (ULONG i = 0; i < 0x100; ++i) {
        if (p[i] == 0x4C && p[i+1] == 0x8D && p[i+2] == 0x35) {
            LONG rel = *(LONG*)(p + i + 3);
            return (PVOID)(p + i + 7 + rel);
        }
    }
    return NULL;
}

static ULONG g_savedCiOptions = 0;
static PULONG g_pCiOptions    = NULL;

static void DisableCi(void) {
    g_pCiOptions = (PULONG)FindCiOptions();
    if (g_pCiOptions) {
        g_savedCiOptions = *g_pCiOptions;
        *g_pCiOptions = 0;
        DbgPrint("[nexus_drv] CI disabled (was 0x%X)\n", g_savedCiOptions);
    } else {
        DbgPrint("[nexus_drv] CI options pointer NOT FOUND — proceeding anyway\n");
    }
}

static void RestoreCi(void) {
    if (g_pCiOptions) {
        *g_pCiOptions = g_savedCiOptions;
        DbgPrint("[nexus_drv] CI restored to 0x%X\n", g_savedCiOptions);
    }
}

// ---- Config (will be settable via IOCTL in a later iteration) -----------
static const WCHAR* g_targetExe = L"cs2.exe";

// ---- Callbacks ----------------------------------------------------------

// SAFER comparison: UNICODE_STRING buffers are NOT guaranteed null-
// terminated. Using _wcsicmp on raw buffer ptrs can read past the end and
// page-fault → BSOD. This routine does length-checked, case-insensitive
// ASCII compare of the basename portion only.
static BOOLEAN BaseNameEqualsI(PCUNICODE_STRING full, const WCHAR* target) {
    if (!full || !full->Buffer || full->Length == 0 || !target) return FALSE;
    const USHORT totalChars = full->Length / sizeof(WCHAR);

    // Find start of basename (after last backslash, or 0 if no backslash).
    USHORT baseStart = 0;
    for (USHORT i = 0; i < totalChars; i++) {
        if (full->Buffer[i] == L'\\') baseStart = (USHORT)(i + 1);
    }
    USHORT baseLen = (USHORT)(totalChars - baseStart);

    // Compute target length (target IS null-terminated since it's a literal).
    USHORT tLen = 0;
    while (target[tLen]) tLen++;
    if (baseLen != tLen) return FALSE;

    for (USHORT i = 0; i < baseLen; i++) {
        WCHAR a = full->Buffer[baseStart + i];
        WCHAR b = target[i];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
        if (a != b) return FALSE;
    }
    return TRUE;
}

VOID ProcessNotify(_In_ PEPROCESS Process,
                   _In_ HANDLE ProcessId,
                   _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (!CreateInfo) return;
    if (!CreateInfo->ImageFileName) return;

    if (BaseNameEqualsI(CreateInfo->ImageFileName, g_targetExe)) {
        DbgPrint("[nexus_drv] TARGET process created: pid=%lu image=%wZ\n",
                 (ULONG)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName);
    }
}

VOID ImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName,
                     _In_ HANDLE ProcessId,
                     _In_ PIMAGE_INFO ImageInfo)
{
    if (!ImageInfo) return;
    if (!FullImageName) return;

    // Only log a small set of "milestone" loads. wZ in DbgPrint takes a
    // PUNICODE_STRING directly and respects its Length, so we can print the
    // full path safely without touching the buffer ourselves.
    if (BaseNameEqualsI(FullImageName, L"kernel32.dll") ||
        BaseNameEqualsI(FullImageName, L"ntdll.dll")    ||
        BaseNameEqualsI(FullImageName, L"cs2.exe"))
    {
        DbgPrint("[nexus_drv] image-load: %wZ in pid=%lu base=%p size=0x%X\n",
                 FullImageName, (ULONG)(ULONG_PTR)ProcessId,
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

    // Disable Code Integrity for our protected-API calls, then restore.
    DisableCi();
    NTSTATUS s1 = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    DbgPrint("[nexus_drv] PsSetCreateProcessNotifyRoutineEx: 0x%08X\n", s1);
    NTSTATUS s2 = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    DbgPrint("[nexus_drv] PsSetLoadImageNotifyRoutine:       0x%08X\n", s2);
    RestoreCi();

    // Keep whichever callback succeeded. PsSetLoadImageNotifyRoutine alone
     // is enough to detect cs2.exe spawn (it fires when each image loads in
     // every process, including the cs2.exe image itself).
    if (!NT_SUCCESS(s1) && !NT_SUCCESS(s2)) {
        DbgPrint("[nexus_drv] BOTH registrations failed — aborting\n");
        return s1;  // both failed; report the first error
    }

    DbgPrint("[nexus_drv] Ready — waiting for %ls (procNotify=%s, imageNotify=%s)\n",
             g_targetExe,
             NT_SUCCESS(s1) ? "ON" : "OFF",
             NT_SUCCESS(s2) ? "ON" : "OFF");
    return STATUS_SUCCESS;
}
