# nexus_drv

Kernel-mode driver for early DLL injection into CS2. Loaded via kdmapper
(BYOVD — Bring Your Own Vulnerable Driver) since we don't have a code-signing
cert. Requires Windows Memory Integrity / Core Isolation to be **OFF** on the
target machine, otherwise kdmapper can't gain kernel access.

## Current state — iteration D4-step-1

Skeleton only. Registers `PsSetCreateProcessNotifyRoutineEx` and
`PsSetLoadImageNotifyRoutine`, logs (via DbgPrint) when cs2.exe is created
and when its kernel32.dll / ntdll.dll / cs2.exe images load. **No injection
yet** — that lands in the next iteration once we verify the notify path
works end-to-end.

## Prerequisites

- **Dev environment** (recommended: an isolated VirtualBox/Hyper-V VM):
  - Visual Studio 2022 Community
  - Workload: Desktop development with C++
  - Windows 11 SDK (matching the WDK version)
  - Windows Driver Kit (WDK) + the VS extension
- **Test environment** (host with the GPU running CS2):
  - Memory Integrity / Core Isolation: **OFF**
  - Test signing optional (kdmapper bypasses signing entirely)

## Build

1. Open `nexus_drv.sln` in Visual Studio (in the dev VM).
2. Solution config: **Release | x64**.
3. Build → Build Solution (F7).
4. Output: `x64\Release\nexus_drv.sys`.

If it errors with "WDK not found", reinstall the WDK VS extension from
`C:\Program Files (x86)\Windows Kits\10\Vsix\VS2022\WDK.vsix`.

## Deploy

1. Copy `nexus_drv.sys` from the VM to the host (shared folder / scp / USB).
2. On host, download kdmapper from https://github.com/TheCruZ/kdmapper.
3. Open elevated cmd:
   ```
   kdmapper.exe nexus_drv.sys
   ```
4. Expect output:
   ```
   [+] Loaded vulnerable driver
   [+] Image base has been allocated at 0x...
   [+] DriverEntry returned 0x0
   ```

## Observe DbgPrint output

1. Download Sysinternals **DebugView**: https://learn.microsoft.com/en-us/sysinternals/downloads/debugview
2. Run `DbgView.exe` as Administrator.
3. **Capture menu** → check **Capture Kernel** (required — without this you see nothing).
4. Optional: Edit → Filter → Include `nexus_drv` to show only our log lines.

When kdmapper loads the driver, you should see:
```
[nexus_drv] DriverEntry — registering callbacks
[nexus_drv] PsSetCreateProcessNotifyRoutineEx: 0x00000000
[nexus_drv] PsSetLoadImageNotifyRoutine:       0x00000000
[nexus_drv] Ready — waiting for cs2.exe
```

Then launch CS2 normally (Steam). You should see:
```
[nexus_drv] TARGET process created: pid=NNNN image=...cs2.exe
[nexus_drv] image-load: ntdll.dll in pid=NNNN base=...
[nexus_drv] image-load: cs2.exe in pid=NNNN base=...
[nexus_drv] image-load: kernel32.dll in pid=NNNN base=...
```

That confirms the kernel notifications fire before CS2's main runs. Next
iteration adds the actual DLL injection at the kernel32.dll image-load
event.

## Uninstall

The driver has no unload routine (kdmapper-mapped drivers can't be cleanly
unloaded). **Reboot to remove**.
