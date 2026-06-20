// nexus_drv.c — early DLL injection driver for CS2.
//
// Architecture:
//   PsSetLoadImageNotifyRoutine catches every image load in every process.
//   When cs2.exe loads → store its PID.
//   When kernel32.dll loads in that PID → spawn a system worker thread that
//     attaches to CS2's address space, walks its PEB to find LoadLibraryA,
//     allocates a small user-mode buffer, writes our DLL path + a tiny
//     shellcode thunk, and queues a user-mode APC to one of CS2's threads.
//   The APC fires the moment CS2's thread enters alertable state (very
//     early), running LoadLibraryA(dllPath) which loads nexus.dll BEFORE
//     CS2's main() compiles a single shader.
//
// kdmapper-loaded — fails the CI check for PsSetCreateProcessNotifyRoutineEx
// but PsSetLoadImageNotifyRoutine works fine without CI bypass.
//
// Hardcoded DLL path: change g_dllPath if nexus.dll moves.

#include <ntddk.h>
#include <wchar.h>

#define NEXUS_DLL_PATH "G:\\cs2-project\\build\\Release\\nexus.dll"

// ---- Undocumented kernel exports we need -------------------------------
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS*);
NTKERNELAPI PPEB     PsGetProcessPeb(PEPROCESS);
NTKERNELAPI NTSTATUS ZwAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NTKERNELAPI VOID     KeStackAttachProcess(PEPROCESS, PKAPC_STATE);
NTKERNELAPI VOID     KeUnstackDetachProcess(PKAPC_STATE);
NTKERNELAPI VOID     KeInitializeApc(PKAPC, PKTHREAD, KAPC_ENVIRONMENT,
                                     PKKERNEL_ROUTINE, PKRUNDOWN_ROUTINE,
                                     PKNORMAL_ROUTINE, KPROCESSOR_MODE, PVOID);
NTKERNELAPI BOOLEAN  KeInsertQueueApc(PKAPC, PVOID, PVOID, KPRIORITY);
NTKERNELAPI VOID     KeTestAlertThread(KPROCESSOR_MODE);

// EPROCESS->ThreadListHead offset on Windows 11 24H2 (10.0.26100). MAY need
// adjustment per CS2-machine Windows build. Verified empirically: 0x5e0 for
// most current Win11 builds.
#define EPROCESS_THREADLIST_OFFSET 0x5E0

// ---- Globals -----------------------------------------------------------
static const WCHAR* g_targetExe = L"cs2.exe";
static HANDLE       g_targetPid = NULL;   // CS2's PID once we detect it
static volatile LONG g_injected = 0;       // 0 = not yet, 1 = done (per-launch)

// ---- BaseNameEqualsI: null-safe length-based compare -------------------
static BOOLEAN BaseNameEqualsI(PCUNICODE_STRING full, const WCHAR* target) {
    if (!full || !full->Buffer || full->Length == 0 || !target) return FALSE;
    const USHORT totalChars = full->Length / sizeof(WCHAR);
    USHORT baseStart = 0;
    for (USHORT i = 0; i < totalChars; i++) {
        if (full->Buffer[i] == L'\\') baseStart = (USHORT)(i + 1);
    }
    USHORT baseLen = (USHORT)(totalChars - baseStart);
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

// ---- PE export resolution ----------------------------------------------
// Given the base address of a loaded DLL in the CURRENT process's address
// space (we KeStackAttachProcess'd into the target), find the address of a
// named export by parsing the export table.
static PVOID FindExport(PVOID dllBase, const char* exportName) {
    if (!dllBase || !exportName) return NULL;
    PUCHAR base = (PUCHAR)dllBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp.VirtualAddress == 0 || exp.Size == 0) return NULL;
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(base + exp.VirtualAddress);

    PULONG names    = (PULONG)(base + ed->AddressOfNames);
    PUSHORT ordinals = (PUSHORT)(base + ed->AddressOfNameOrdinals);
    PULONG funcs    = (PULONG)(base + ed->AddressOfFunctions);

    for (ULONG i = 0; i < ed->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        const char* a = name, *b = exportName;
        while (*a && (*a == *b)) { a++; b++; }
        if (*a == 0 && *b == 0) {
            return base + funcs[ordinals[i]];
        }
    }
    return NULL;
}

// ---- PEB walk to find kernel32.dll base in target process --------------
// Must be called while attached to the target (KeStackAttachProcess).
static PVOID FindKernel32Base(PEPROCESS proc) {
    PPEB peb = PsGetProcessPeb(proc);
    if (!peb) return NULL;
    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return NULL;

    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    for (PLIST_ENTRY cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (BaseNameEqualsI(&e->BaseDllName, L"kernel32.dll")) {
            return e->DllBase;
        }
    }
    return NULL;
}

// ---- APC routines ------------------------------------------------------
// The KernelRoutine runs at PASSIVE_LEVEL in kernel mode before the APC is
// dispatched. We use it just to free the APC structure (we allocated it
// on the non-paged pool). The NormalRoutine is what actually runs in user
// mode — but for our shellcode-injection, NormalRoutine is the shellcode
// address itself (in user memory), so this kernel routine has no work.
static VOID NTAPI ApcKernelRoutine(PKAPC Apc,
                                   PKNORMAL_ROUTINE* NormalRoutine,
                                   PVOID* NormalContext,
                                   PVOID* SystemArgument1,
                                   PVOID* SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);
}

// ---- Shellcode template ------------------------------------------------
// x64 shellcode that calls LoadLibraryA(dllPath) then returns to original
// RIP (saved on stack by the APC dispatcher).
//
// Bytes:
//   48 83 EC 28              sub rsp, 28h           ; shadow space
//   48 8D 0D 11 00 00 00      lea rcx, [rip + 0x11] ; -> dllPath
//   48 B8 ?? ?? ?? ?? ?? ?? ?? ??  mov rax, <LoadLibraryA addr>
//   FF D0                    call rax
//   48 83 C4 28              add rsp, 28h
//   C3                       ret
//   <dllPath bytes, null terminated>
static const UCHAR g_shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,                                  // sub rsp, 28h
    0x48, 0x8D, 0x0D, 0x11, 0x00, 0x00, 0x00,                // lea rcx, [rip + 0x11]
    0x48, 0xB8, 0,0,0,0,0,0,0,0,                             // mov rax, <imm64>
    0xFF, 0xD0,                                              // call rax
    0x48, 0x83, 0xC4, 0x28,                                  // add rsp, 28h
    0xC3,                                                    // ret
};
static const SIZE_T SHELLCODE_LOADLIB_OFFSET = 13;  // offset of imm64 in mov rax
static const SIZE_T SHELLCODE_LEN            = sizeof(g_shellcode);

// ---- Injection worker --------------------------------------------------
// Runs as a system thread so we have a normal context and PASSIVE_LEVEL.
static VOID NTAPI InjectWorker(PVOID Context) {
    HANDLE pid = (HANDLE)Context;
    DbgPrint("[nexus_drv] InjectWorker: started for pid=%lu\n", (ULONG)(ULONG_PTR)pid);

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(s) || !proc) {
        DbgPrint("[nexus_drv] InjectWorker: PsLookupProcessByProcessId 0x%X\n", s);
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(proc, &apcState);

    // 1. Find kernel32.dll + LoadLibraryA in target.
    PVOID k32 = FindKernel32Base(proc);
    PVOID loadLib = k32 ? FindExport(k32, "LoadLibraryA") : NULL;
    DbgPrint("[nexus_drv] InjectWorker: kernel32=%p LoadLibraryA=%p\n", k32, loadLib);

    if (!loadLib) {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(proc);
        DbgPrint("[nexus_drv] InjectWorker: couldn't resolve LoadLibraryA, aborting\n");
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    // 2. Allocate user-mode memory in target for shellcode + DLL path.
    SIZE_T regionSize = 0x1000;
    PVOID userBuf = NULL;
    s = ZwAllocateVirtualMemory(NtCurrentProcess(), &userBuf, 0, &regionSize,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(s) || !userBuf) {
        DbgPrint("[nexus_drv] InjectWorker: ZwAllocateVirtualMemory 0x%X\n", s);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(proc);
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }
    DbgPrint("[nexus_drv] InjectWorker: allocated user buf at %p (size=%llu)\n",
             userBuf, (ULONG64)regionSize);

    // 3. Build the buffer: [shellcode][dllPath null-terminated]
    const char* dllPath = NEXUS_DLL_PATH;
    SIZE_T pathLen = 0;
    while (dllPath[pathLen]) pathLen++;
    pathLen++;  // include null terminator

    RtlCopyMemory(userBuf, g_shellcode, SHELLCODE_LEN);
    *(PVOID*)((PUCHAR)userBuf + SHELLCODE_LOADLIB_OFFSET) = loadLib;
    RtlCopyMemory((PUCHAR)userBuf + SHELLCODE_LEN, dllPath, pathLen);

    // 4. Find a thread to APC. Walk EPROCESS->ThreadListHead.
    PLIST_ENTRY threadList = (PLIST_ENTRY)((PUCHAR)proc + EPROCESS_THREADLIST_OFFSET);
    PETHREAD targetThread = NULL;
    // ETHREAD->ThreadListEntry offset varies — just take the first node.
    if (threadList->Flink != threadList) {
        // Trust that the first ThreadListEntry CONTAINING_RECORD gives a valid ETHREAD.
        // (Risky but standard pattern; tweak ETHREAD offset if BSOD here.)
        targetThread = (PETHREAD)((PUCHAR)threadList->Flink - 0x4E8); // typical ThreadListEntry offset
    }
    if (!targetThread) {
        DbgPrint("[nexus_drv] InjectWorker: no thread found\n");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(proc);
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }
    DbgPrint("[nexus_drv] InjectWorker: target thread=%p\n", targetThread);

    // 5. Build + queue user APC. NormalRoutine = our shellcode address.
    PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'cAxN');
    if (!apc) {
        DbgPrint("[nexus_drv] InjectWorker: ExAllocatePool2 failed\n");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(proc);
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    KeInitializeApc(apc,
                    (PKTHREAD)targetThread,
                    OriginalApcEnvironment,
                    ApcKernelRoutine,
                    NULL,
                    (PKNORMAL_ROUTINE)userBuf,   // NormalRoutine = shellcode in user mem
                    UserMode,
                    NULL);

    BOOLEAN inserted = KeInsertQueueApc(apc, NULL, NULL, 0);
    DbgPrint("[nexus_drv] InjectWorker: KeInsertQueueApc inserted=%d\n", (int)inserted);

    if (inserted) {
        // Force the thread into alertable state so APC dispatches.
        KeTestAlertThread(UserMode);
        DbgPrint("[nexus_drv] InjectWorker: APC queued for thread, KeTestAlertThread fired\n");
    } else {
        ExFreePool(apc);
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(proc);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ---- Image-load callback ----------------------------------------------
VOID ImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName,
                     _In_ HANDLE ProcessId,
                     _In_ PIMAGE_INFO ImageInfo)
{
    if (!ImageInfo) return;
    if (!FullImageName) return;

    if (BaseNameEqualsI(FullImageName, L"cs2.exe")) {
        g_targetPid = ProcessId;
        InterlockedExchange(&g_injected, 0);  // reset for new launch
        DbgPrint("[nexus_drv] cs2.exe load — tracking pid=%lu\n",
                 (ULONG)(ULONG_PTR)ProcessId);
        return;
    }

    if (g_targetPid && ProcessId == g_targetPid &&
        BaseNameEqualsI(FullImageName, L"kernel32.dll"))
    {
        // Inject exactly once per launch.
        if (InterlockedCompareExchange(&g_injected, 1, 0) == 0) {
            DbgPrint("[nexus_drv] kernel32.dll loaded in cs2 pid=%lu — spawning injector\n",
                     (ULONG)(ULONG_PTR)ProcessId);
            HANDLE workerHandle = NULL;
            NTSTATUS s = PsCreateSystemThread(&workerHandle, GENERIC_ALL, NULL, NULL, NULL,
                                              InjectWorker, (PVOID)ProcessId);
            if (NT_SUCCESS(s) && workerHandle) {
                ZwClose(workerHandle);
            } else {
                DbgPrint("[nexus_drv] PsCreateSystemThread failed 0x%X\n", s);
            }
        }
    }
}

VOID ProcessNotify(_In_ PEPROCESS Process,
                   _In_ HANDLE ProcessId,
                   _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
    // Unused — left here in case CI bypass later succeeds.
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[nexus_drv] DriverEntry — APC injection enabled\n");
    DbgPrint("[nexus_drv] Target DLL: %s\n", NEXUS_DLL_PATH);

    NTSTATUS s = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[nexus_drv] PsSetLoadImageNotifyRoutine failed 0x%X\n", s);
        return s;
    }

    DbgPrint("[nexus_drv] Ready — waiting for %ls\n", g_targetExe);
    return STATUS_SUCCESS;
}
