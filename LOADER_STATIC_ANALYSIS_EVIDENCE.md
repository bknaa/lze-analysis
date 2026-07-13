# Static Analysis Evidence — Laze_Loader.exe

> Analysis method: command-line static analysis (`objdump -x`, `objdump -d`, `strings` in both
> ASCII and UTF-16LE modes, hash utilities) on a Linux host. No debugger or interactive
> disassembler (x64dbg / dnSpy / Ghidra) was used. All data below is raw tool output.
>
> **Note on .NET string extraction:** this binary is a .NET (CLR) assembly. .NET string literals
> are stored as UTF-16LE in the metadata `#US` heap, so a plain ASCII `strings` pass misses most of
> them (method/type names still show up in ASCII because .NET metadata names are stored as UTF-8
> in the `#Strings` heap). Both passes were run; results are kept separate below so the extraction
> method for each string is traceable.

---

## 1. File Identity & Hashes

```
File type   : PE32+ executable (console) x86-64, Mono/.NET assembly
Sections    : 2 (.text, .rsrc)
Size        : 120,832 bytes
Subsystem   : Windows CUI (console)
Target FW   : .NET Framework 4.6.1
Assembly    : Laze.Loader, Version 1.2.0.0
Product     : "Laze Loader"

SHA256: c0122c25beb71df212695fb968c2fd6cf66039d8841e3245ad49475e0a44d590
SHA1:   9dc2c87f59736f9f826a43c001e1235c4012af4e
MD5:    5734f1ee099aed396c37d76dca2142ce
```

## 2. PE Header (raw `objdump -x` output, header section)

```
architecture: i386:x86-64, flags 0x0000012f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_LOCALS, D_PAGED
start address 0x0000000000000000

Characteristics 0x22
	executable
	large address aware

Time/Date		8854d410	(This is a reproducible build file hash, not a timestamp)
Magic			020b	(PE32+)
MajorLinkerVersion	48
MinorLinkerVersion	0
SizeOfCode		0000000000002400
SizeOfInitializedData	000000000001b200
AddressOfEntryPoint	0000000000000000
ImageBase		0000000140000000
Subsystem		00000003	(Windows CUI)
DllCharacteristics	00008560
				HIGH_ENTROPY_VA
				DYNAMIC_BASE
				NX_COMPAT
				NO_SEH
				TERMINAL_SERVICE_AWARE

The Data Directory
Entry 2 0000000000006000 0001b0cc Resource Directory [.rsrc]
Entry 6 0000000000004170 00000038 Debug Directory
```

**Interpretation:** `AddressOfEntryPoint = 0` is expected for a pure-IL .NET assembly — execution
starts via the CLR bootstrap (`_CorExeMain` in `mscoree.dll`, referenced through the CLR header),
not through native `.text` code. The `.text` section (0x2400 bytes) mostly holds the CLR header
and metadata tables rather than disassemblable x86 instructions; a disassembly of it produces
metadata bytes misread as junk opcodes and is not included here as it would be misleading. The
`.rsrc` section (0x1b0cc = ~110 KB) is disproportionately large relative to `.text` — consistent
with embedded resources (icon, version info, and/or an embedded payload) rather than code.

"Reproducible build file hash" in place of a real timestamp indicates this was compiled with
.NET's deterministic build flag enabled — the PE timestamp field is intentionally replaced with a
hash for build reproducibility, so **compile time cannot be recovered from this field.**

## 3. Sections

```
Idx Name          Size      VMA               File off
  0 .text         00002204  0000000140002000  00000200   CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rsrc         0001b0cc  0000000140006000  00002600   CONTENTS, ALLOC, LOAD, READONLY, DATA
```

## 4. Manifest (embedded XML, raw ASCII string extraction)

```xml
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="1.0.0.0" name="MyApplication.app"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
```

**Note:** the internal manifest `name="MyApplication.app"` is a leftover default project name —
suggests the developer never customized the manifest identity, only the visible product strings
(FileDescription, ProductName, etc. — see §7). The binary requires **administrator privileges** to
run (`requireAdministrator`).

## 5. .NET Metadata Method/Type Names (raw ASCII `strings -n 6`, `#Strings` heap)

The assembly is **not obfuscated** — no ConfuserEx/.NET Reactor renaming was applied. Method and
field names are fully readable and self-descriptive:

```
Program
find_target_process
get_kernel32_base_address
allocate_and_write_memory
create_remote_thread
inject
update_dll
should_update
get_dll_path
show_announcement
compute_sha1
dll_path_addr
loader_version
announcement_text
h_process
kernel_handle
```

Cross-referenced Win32 API imports appearing in the same heap (used via P/Invoke, not classic PE
imports — see §6 for why):

```
CreateRemoteThread
VirtualAllocEx
WriteProcessMemory
GetProcAddress
GetCurrentProcess
LoadLibraryA
```

.NET framework types used (from `mscorlib`, confirming networking/crypto/process-management
capability):

```
System.Net            (WebClient, WebRequest, WebResponse, ServicePointManager, SecurityProtocolType)
System.Net.WebClient   → DownloadData, DownloadString
System.Security.Cryptography  (HashAlgorithm, ComputeHash → compute_sha1)
System.Diagnostics     (ProcessModuleCollection, GetProcesses, get_MainWindowTitle, get_ProcessName)
System.Threading
System.Security.Principal  (WindowsIdentity, SecurityIdentifier, get_Owner, get_User)
System.IO              (FileStream, DirectoryInfo, WriteAllBytes, GetFolderPath)
```

## 6. P/Invoke Win32 API Usage (via .NET metadata, not classic PE import table)

Because this is a managed .NET binary, native Win32 calls go through `DllImport`/P/Invoke rather
than a standard PE import table — `objdump -x` shows no meaningful `Import Directory` (Entry 1 is
zeroed). The relevant native functions are instead visible as metadata references to
`kernel32.dll`:

```
kernel32.dll:
  CreateRemoteThread   ← thread creation in the target process
  VirtualAllocEx       ← memory allocation in the target process (flAllocationType, flProtect params present)
  WriteProcessMemory    ← writes DLL path string into allocated memory
  GetProcAddress        ← resolves LoadLibraryA address at runtime
  GetCurrentProcess
```

Associated parameter-name metadata confirms classic parameters: `lpThreadId`, `lpParameter`,
`lpStartAddress`, `lpBaseAddress`, `dwStackSize`, `dwCreationFlags`, `lpNumberOfBytesWritten`,
`hProcess`, `hModule`.

## 7. Version / Product Resource Info (UTF-16LE `strings`)

```
VS_VERSION_INFO
FileDescription   : Laze Loader
FileVersion       : 1.2.0.0
InternalName      : Laze.Loader.exe
OriginalFilename  : Laze.Loader.exe
ProductName       : Laze Loader
ProductVersion    : 1.2.0.0
Assembly Version  : 1.2.0.0
```

## 8. Network Endpoints & Target Identification (UTF-16LE `strings` — NOT found in plain ASCII pass)

```
https://raw.githubusercontent.com/aaleaf/Files/main/data      — version/update-check endpoint
https://github.com/aaleaf/Files/raw/main/Bin/laze.dll          — payload DLL download URL
https://github.com/aaleaf/Laze                                 — project homepage (shown to user in an update prompt)

Target window titles (used for process discovery):
  craftrise-x64
  sonoyuncuclient

Payload filename written to disk / referenced: laze.dll
Native DLL referenced for LoadLibraryA resolution: kernel32.dll
```

No Discord webhook URLs, no IP-literal C2 addresses, and no telemetry/analytics endpoints were
found in either string pass.

## 9. User-Facing Log/Status Strings (UTF-16LE `strings`, original Turkish)

```
laze-loader
Uygulamayı yönetici olarak başlatın.      [paraphrased: "run the app as administrator"]
Veriler kontrol ediliyor.                  ["Checking data."]
Duyuru mevcut: {0}                         ["Announcement available: {0}"]
Laze Loader güncel değil.                  ["Laze Loader is not up to date."]
Yeni sürüm mevcut: {0} https://github.com/aaleaf/Laze adresinden indirin.
Laze başlatılıyor.                         ["Laze is starting."]
Bir hata meydana geldi: {0}                ["An error occurred: {0}"]
Oyun tespit edilemedi.                     ["Game could not be detected."]
Kernel32 bulunamadı.                       ["Kernel32 not found."]
Oyuna erişilemedi.                         ["Could not access the game."]
Laze yüklendi. ({0} ms)                    ["Laze loaded. ({0} ms)"]
Oyun hafızasında alan oluşturulamadı.      ["Could not allocate memory in game."]
Dll dosya konumu yüklenemedi.              ["DLL file location could not be loaded."]
Remote thread oluşturulamadı.              ["Remote thread could not be created."]
```

(English glosses added in brackets for readability; the strings themselves are the literal raw
extraction, only lightly re-flowed since the UTF-16 extraction splits some Turkish characters with
diacritics.)

## 10. Reconstructed Execution Flow

Based on the method names (§5), P/Invoke targets (§6), and log strings (§9), the control flow is:

```
1. show_announcement()      — fetches https://raw.githubusercontent.com/aaleaf/Files/main/data,
                               displays LOADERVERSION / SHOWANNOUNCEMENT / ANNOUNCEMENTTEXT fields
2. should_update()           — compares local loader_version against fetched LOADERVERSION
3. update_dll()               — if payload missing/outdated: WebClient.DownloadData() from
                               https://github.com/aaleaf/Files/raw/main/Bin/laze.dll,
                               compute_sha1() to verify integrity, WriteAllBytes() to local path
4. find_target_process()     — GetProcesses() + get_MainWindowTitle() matching "craftrise-x64" /
                               "sonoyuncuclient"
5. get_kernel32_base_address() + GetProcAddress → resolves LoadLibraryA address in target process
6. allocate_and_write_memory() — OpenProcess (implicit via ProcessModule handle) →
                               VirtualAllocEx → WriteProcessMemory (writes the DLL path string)
7. create_remote_thread() → inject()  — CreateRemoteThread(hProcess, NULL, 0, LoadLibraryA_addr,
                               dll_path_addr, 0, &lpThreadId)
```

This is the **classic `LoadLibraryA` + `CreateRemoteThread` injection technique** — not manual
mapping, not a hook-based method. It relies on the target process loading `laze.dll` through the
normal Windows loader, which means the payload DLL's own `DllMain`/exports run exactly as they
would for a legitimately loaded module.

## 11. CIL Bytecode-Level Verification (manual metadata/IL parsing)

Sections 1–10 identify method names and API targets from .NET metadata, but do not confirm the
actual constant values passed to the injection APIs. To verify this, the CLR header, metadata
stream headers, and `MethodDef` table were parsed by hand (via a small Python script reading raw
PE structures — no decompiler was used), locating the RVA and IL body of each method of interest
and manually disassembling the CIL opcodes.

### 11.1 Method table (from parsed `MethodDef`, `#~` stream)

```
Main                          RVA=0x2048
start                         RVA=0x2094
inject                        RVA=0x224c
find_target_process           RVA=0x2350
get_kernel32_base_address     RVA=0x23c0
get_dll_path                  RVA=0x2448
should_update                 RVA=0x2480
update_dll                    RVA=0x24fc
allocate_and_write_memory     RVA=0x25a8
create_remote_thread          RVA=0x2628
compute_sha1                  RVA=0x267c
log                           RVA=0x26d0

VirtualAllocEx / WriteProcessMemory / CreateRemoteThread / GetProcAddress
    RVA=0x0, ImplFlags=0x80 (PreserveSig), Flags=0x2096 (PinvokeImpl | Static | HideBySig)
    — confirmed P/Invoke declarations, no managed body (as expected).
```

### 11.2 `allocate_and_write_memory` — raw CIL disassembly (relevant excerpt)

```
ldarg.2
ldarg.0
ldsfld    token=0x0a00001a        ; static field ref (consistent with System.IntPtr.Zero)
ldarg.1
callvirt  token=0x0a000037
ldc.i4    12288                   ; 0x3000 = MEM_COMMIT (0x1000) | MEM_RESERVE (0x2000)
ldc.i4.4                          ; 4 = PAGE_READWRITE
call      token=0x0600000f        ; VirtualAllocEx(hProcess, lpAddress, dwSize, 0x3000, 4)
```

**Finding:** memory is allocated in the target process with `PAGE_READWRITE` protection — **not**
`PAGE_EXECUTE_READWRITE`. This confirms the allocated region is used to hold data (the DLL path
string for `WriteProcessMemory`), not executable shellcode. The actual code execution is delegated
entirely to the legitimate Windows loader via `LoadLibraryA`, executed through the remote thread
described below — this injector does not write or run shellcode of its own.

### 11.3 `create_remote_thread` — raw CIL disassembly (relevant excerpt)

```
ldarg.0
ldsfld   token=0x0a00001a
ldc.i4.0
ldarg.1
ldstr    token=0x70000541
call     token=0x06000012
ldarg.2
ldc.i4.0                          ; dwCreationFlags = 0
ldsfld   token=0x0a00001a
call     token=0x06000011         ; CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, lpParameter, 0, out lpThreadId)
```

**Finding:** `dwCreationFlags = 0` — the `CREATE_SUSPENDED` flag (`0x4`) is never used anywhere in
this method. The remote thread begins executing immediately upon creation; there is no
suspend/resume step, no thread context manipulation, and no attempt to hide the thread's start
address.

### 11.4 Consolidated memory-integrity summary

The complete set of operations this loader performs against the target (CraftRise) process's
memory, in order, with confirmed parameters:

```
1. OpenProcess           (implicit, via ProcessModule handle from find_target_process)
2. VirtualAllocEx        (hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE (0x3000), PAGE_READWRITE (4))
3. WriteProcessMemory     (hProcess, allocatedAddr, <UTF path string of laze.dll>, size)
4. GetProcAddress         (kernel32 module handle, "LoadLibraryA")   — resolved locally, not remotely
5. CreateRemoteThread     (hProcess, NULL, 0, <LoadLibraryA address>, allocatedAddr, 0 /*not suspended*/, &threadId)
```

No shellcode is written. No executable memory is allocated. No thread hijacking, no
`SetThreadContext`/APC queuing, no manual PE mapping is used anywhere in this loader — this is the
textbook/minimal form of `LoadLibrary`-based remote injection, distinguishable at the API-parameter
level (RW-only allocation, immediate non-suspended thread start) from more evasive variants (e.g.
the companion `TealipInjector` analyzed separately, which avoids `CreateRemoteThread` entirely via
`SetWindowsHookExW`).

---

## Honest scope of this evidence

- No dynamic/runtime analysis was performed — the loader was not executed, and network requests to
  the GitHub URLs above were not made. The download/update flow described in §10 is reconstructed
  from method names and string literals, not observed traffic.
- The exact byte-level sequence of API calls (e.g., precise order of `VirtualAllocEx` parameters)
  is inferred from .NET metadata naming conventions and string association, not from decompiled IL
  or a debugger trace — a full IL decompilation (e.g., via ILSpy/dnSpy) would be needed to confirm
  exact call ordering and argument values with certainty.
- All hashes, strings, and header fields above are copied verbatim from tool output.
- The CIL disassembly in §11 was produced by a hand-written PE/metadata parser (custom Python, not
  a decompiler), and only decodes the common single-byte opcode set — not every `MemberRef`/`Field`
  token was cross-resolved to its fully-qualified name (e.g. token `0x0a00001a` is inferred to be
  `System.IntPtr.Zero` from usage pattern, not confirmed via full `TypeRef`/`MemberRef` chain
  resolution). The two constant values central to the memory-integrity finding (`12288` /
  `0x3000` and `4`) were read directly as raw IL immediate operands and are exact, not inferred.
