# Static Analysis Evidence — Laze.dll

> Analysis method: command-line static analysis (`objdump -x`, `objdump -d`, `strings` in both
> ASCII and UTF-16LE modes, hash utilities) on a Linux host. No debugger or interactive
> disassembler (x64dbg / Ghidra) was used. All data below is raw tool output.
>
> **Note on VMProtect:** this binary is wrapped with VMProtect (see §3). VMProtect virtualizes code
> into a custom bytecode interpreted at runtime and typically encrypts string literals, so most
> feature-identifying strings and the true control flow are **not recoverable through static
> analysis alone**. What follows is everything that remains visible despite the protection — mainly
> the import table (VMProtect does not hide imports by default) and the small set of strings stored
> outside the protected regions (version resource).

---

## 1. File Identity & Hashes

```
File type   : PE32+ executable (DLL), Windows GUI subsystem, x86-64
Sections    : 10 (.text, .rdata, .data, .pdata, .fptable, .vmp0, .vmp1, .vmp2, .rsrc, .reloc)
Size        : 1,148,416 bytes

SHA256: 6ed0674e02ef61821a4d458c4a7d97258715efaaa1b672a81b22073a42f4868b
SHA1:   5ee57fae7a07da4b442416e6bb923d4ea0283da4
MD5:    5dd5ad391ff4145fef6ed70112bb800d
```

## 2. PE Header (raw `objdump -x` output, header section)

```
architecture: i386:x86-64, flags 0x0000012f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_LOCALS, D_PAGED
start address 0x0000000180296d57

Characteristics 0x2022
	executable
	large address aware
	DLL

Time/Date		Wed Oct 22 17:09:13 2025
Magic			020b	(PE32+)
MajorLinkerVersion	14
MinorLinkerVersion	44
SizeOfCode		00000000000c0600
SizeOfInitializedData	00000000000b7800
AddressOfEntryPoint	0000000000296d57
ImageBase		0000000180000000
Subsystem		00000002	(Windows GUI)
DllCharacteristics	00000160
				HIGH_ENTROPY_VA
				DYNAMIC_BASE
				NX_COMPAT
```

**Caveat on the timestamp:** `MajorLinkerVersion 14 / MinorLinkerVersion 44` corresponds to a
Visual Studio 2015-era MSVC linker, consistent with an Oct 2025 native C++ build. However, PE
timestamps are trivially forgeable and VMProtect-wrapped binaries sometimes preserve the original
compiler timestamp and sometimes don't — treat this date as *plausible* build evidence, not proof.

## 3. Section Layout — VMProtect Signature

```
Idx Name          Size      VMA               File off
  0 .text         00000000  0000000180001000  00000000   ALLOC, LOAD, READONLY, CODE   (empty!)
  1 .rdata        00000000  00000001800c2000  00000000   ALLOC, LOAD, READONLY, DATA   (empty!)
  2 .data         00000000  00000001800ea000  00000000   ALLOC, LOAD, DATA              (empty!)
  3 .pdata        00000000  0000000180172000  00000000   ALLOC, LOAD, READONLY, DATA    (empty!)
  4 .fptable      00000000  000000018017a000  00000000   ALLOC, LOAD, DATA              (empty!)
  5 .vmp0         00000000  000000018017b000  00000000   ALLOC, LOAD, READONLY, CODE    (empty!)
  6 .vmp1         00000658  0000000180199000  00000400   CONTENTS, ALLOC, LOAD, DATA
  7 .vmp2         00117240  000000018019a000  00000c00   CONTENTS, ALLOC, LOAD, READONLY, CODE, DATA
  8 .rsrc         000003b1  00000001802b2000  00118000   CONTENTS, ALLOC, LOAD, READONLY, DATA
  9 .reloc        00000058  00000001802b3000  00118400   CONTENTS, ALLOC, LOAD, READONLY, DATA
```

**`.vmp0` / `.vmp1` / `.vmp2` section names are a direct, unambiguous VMProtect signature.** The
original `.text`/`.rdata`/`.data`/`.pdata`/`.fptable` sections are all zero-sized in the file — the
real code and much of the data originally in those sections have been relocated into `.vmp2`
(1.1 MB — the overwhelming majority of the file) as virtualized bytecode. `AddressOfEntryPoint`
(`0x296d57`) lands inside `.vmp2`, confirming execution starts in VM-protected code, not in
original `.text`.

A short disassembly at the entry point illustrates why further static disassembly is not
productive:

```
0000000180296d57 <.vmp2+0xfcd57>:
   180296d57:	e8 51 de fe ff       	call   0x180284bad
   180296d5c:	00 00                	add    BYTE PTR [rax],al
   180296d5e:	67 6c                	ins    BYTE PTR es:[edi],dx
   180296d61:	65 72 74             	gs jb  0x180296dd8
   180296d67:	64 00 80 cf 64 c9 74 	add    BYTE PTR fs:[rax+0x74c964cf],al
   ...
```

Only the first instruction (`call 0x180284bad`, the jump into the VM dispatcher) is meaningful;
everything after it is virtualized bytecode/data misinterpreted as x86 by a linear disassembler,
not real instructions. Recovering actual logic here would require a VM-devirtualization tool or
dynamic tracing, not `objdump`.

## 4. Import Address Table (raw `objdump -x` output — VMProtect does NOT hide this)

```
DLL Name: KERNEL32.dll   (127 functions imported — full categorized list below)
DLL Name: USER32.dll     (31 functions)
DLL Name: OPENGL32.dll   (25 functions)
DLL Name: WINMM.dll      (1 function: PlaySoundA)
```

### KERNEL32.dll — grouped by function

```
Process/thread enumeration & control:
  CreateToolhelp32Snapshot, Thread32First, Thread32Next, OpenThread,
  SuspendThread, ResumeThread, GetThreadContext, SetThreadContext,
  GetCurrentThreadId, GetCurrentProcess, GetCurrentProcessId, CreateThread

Memory management:
  VirtualAlloc, VirtualFree, VirtualQuery, VirtualProtect,
  HeapCreate, HeapAlloc, HeapReAlloc, HeapFree, HeapDestroy, HeapSize, GetProcessHeap
  GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock

Module/library:
  LoadLibraryA, LoadLibraryExW, FreeLibrary, FreeLibraryAndExitThread,
  GetProcAddress, GetModuleHandleA, GetModuleHandleW, GetModuleHandleExW,
  GetModuleFileNameW, DisableThreadLibraryCalls

Anti-debug / integrity:
  IsDebuggerPresent, SetUnhandledExceptionFilter, UnhandledExceptionFilter,
  RaiseException, RtlCaptureContext, RtlLookupFunctionEntry, RtlVirtualUnwind,
  RtlUnwind, RtlUnwindEx, RtlPcToFileHeader, FlushInstructionCache

File I/O:
  CreateFileW, ReadFile, WriteFile, FindFirstFileW, FindFirstFileExW,
  FindNextFileW, FindClose, CreateDirectoryW, GetFileAttributesExW,
  GetFileSizeEx, SetFilePointerEx, SetEndOfFile, SetFileInformationByHandle,
  GetFileInformationByHandleEx, GetFileType

Timing:
  QueryPerformanceCounter, QueryPerformanceFrequency, GetTickCount64,
  GetSystemTimeAsFileTime, Sleep, WaitForSingleObject, WaitForSingleObjectEx

Sync primitives:
  InitializeCriticalSectionAndSpinCount, InitializeCriticalSectionEx,
  EnterCriticalSection, LeaveCriticalSection, DeleteCriticalSection,
  AcquireSRWLockExclusive, ReleaseSRWLockExclusive, TryAcquireSRWLockExclusive,
  TlsAlloc, TlsFree, TlsGetValue, TlsSetValue,
  FlsAlloc, FlsFree, FlsGetValue, FlsSetValue,
  InitializeSListHead, InterlockedFlushSList

Locale/string:
  MultiByteToWideChar, WideCharToMultiByte, GetLocaleInfoA, GetLocaleInfoW,
  GetLocaleInfoEx, LCMapStringW, LCMapStringEx, CompareStringW, GetStringTypeW,
  IsValidCodePage, IsValidLocale, GetUserDefaultLCID, EnumSystemLocalesW,
  GetOEMCP, GetACP, GetCPInfo

Process creation / exit:
  CreateProcessW, GetExitCodeProcess, GetExitCodeThread, TerminateProcess,
  ExitProcess, ExitThread

Console/env:
  GetCommandLineW, GetCommandLineA, GetEnvironmentStringsW,
  FreeEnvironmentStringsW, SetEnvironmentVariableW, GetStdHandle, SetStdHandle,
  GetConsoleMode, GetConsoleOutputCP, WriteConsoleW, ReadConsoleW,
  FlushFileBuffers, AreFileApisANSI, FormatMessageA, GetLastError, SetLastError,
  LocalFree, EncodePointer, DecodePointer, IsProcessorFeaturePresent, GetSystemInfo
```

### USER32.dll — input & window functions

```
Input simulation:      SendInput, keybd_event, SetCursorPos
Input reading:         GetAsyncKeyState, GetKeyState, GetMessageExtraInfo
Cursor/capture:        GetCursorPos, SetCursor, LoadCursorA, SetCapture, ReleaseCapture,
                        GetCapture, TrackMouseEvent
Coordinate conversion: ClientToScreen, ScreenToClient, GetClientRect, GetWindowRect,
                        WindowFromPoint, WindowFromDC
Window/message:        GetForegroundWindow, SetWindowLongPtrA, SendMessageA, PostMessageA,
                        CallWindowProcA, IsWindowUnicode
Keyboard layout:       GetKeyboardLayout
Clipboard:             OpenClipboard, CloseClipboard, EmptyClipboard, GetClipboardData,
                        SetClipboardData
Dialogs:                MessageBoxA
```

### OPENGL32.dll — rendering (immediate-mode drawing)

```
glBegin, glEnd, glVertex3f, glVertex3d, glColor3f, glColor4f, glLineWidth,
glEnable, glDisable, glDepthMask, glAlphaFunc, glBlendFunc, glHint, glShadeModel,
glPolygonOffset, glPushAttrib, glPopAttrib, glPushMatrix, glPopMatrix,
glLoadMatrixf, glLoadIdentity, glMatrixMode, glTranslatef, glScaled, glGetFloatv
```

### WINMM.dll

```
PlaySoundA
```

## 5. Interpretation of Import Table

The import table alone (imports are not hidden by VMProtect, only the code that calls them) is
sufficient to characterize this DLL's capability set without needing the protected strings:

- **`glBegin`/`glEnd`/`glVertex3f`/`glVertex3d`/`glColor3f`/`glColor4f`/`glLineWidth` and matrix
  functions (`glPushMatrix`/`glLoadMatrixf`/`glTranslatef`)** — this is the exact function set used
  for immediate-mode OpenGL overlay drawing (boxes, lines, 3D-to-2D projected shapes). This is
  consistent with an **ESP/wallhack rendering overlay** drawn directly into the target game's
  OpenGL context (the DLL does not create its own window — it imports OpenGL functions to draw
  into whatever context is already current, i.e., the host game's).
- **`SendInput`, `keybd_event`, `SetCursorPos`** alongside **`GetAsyncKeyState`/`GetKeyState`**
  — input simulation combined with input polling is consistent with **automated aim/movement
  assistance** (the polling functions read hotkey state; the simulation functions move the
  cursor/send input).
- **`ClientToScreen`/`ScreenToClient`/`GetClientRect`/`GetWindowRect`/`WindowFromPoint`** — screen
  ↔ client coordinate conversion, needed to translate in-game 3D world positions to 2D screen
  coordinates for ESP rendering and/or to translate screen clicks to game-relative coordinates for
  input simulation.
- **`CreateToolhelp32Snapshot`/`Thread32First`/`Thread32Next`/`OpenThread`/
  `SuspendThread`/`ResumeThread`/`GetThreadContext`/`SetThreadContext`** — thread enumeration and
  full context manipulation of arbitrary threads in the process. This goes beyond what a rendering
  overlay needs; possible uses include self-protection (suspending threads that might be scanning
  it) or manipulating the host application's own threads. Cannot be confirmed further without
  dynamic analysis.
- **`IsDebuggerPresent` + `SetUnhandledExceptionFilter`/`UnhandledExceptionFilter`** — standard
  anti-debug/anti-crash-reporting pattern.
- **Clipboard functions** (`OpenClipboard`/`GetClipboardData`/`SetClipboardData`) — purpose unclear
  from imports alone; could relate to config import/export via clipboard, a common lightweight UX
  pattern for cheat menus that don't want to touch disk. Speculative — flagged as such.

## 6. Version Resource Info (UTF-16LE `strings`)

```
VS_VERSION_INFO
FileDescription   : github.com/aaleaf/laze
FileVersion       : 1, 0, 0, 0
InternalName      : laze.dll
OriginalFilename  : laze.dll
ProductName       : Laze Free
ProductVersion    : 1.0.0.0
```

This confirms: (1) the product is self-branded as **"Laze Free"**, i.e. a free-tier build of a
named cheat product, and (2) the same `github.com/aaleaf/laze` project association as the loader's
download URLs (`github.com/aaleaf/Files`, `github.com/aaleaf/Laze`), directly linking this DLL to
the loader analyzed in the companion document.

## 7. What Was NOT Found (and why)

```
- No PDB debug path            → likely stripped, or never embedded; VMProtect wrapping can also
                                  remove/relocate debug directory contents.
- No plaintext feature strings  → VMProtect encrypts/virtualizes string literals used within
  (menu labels, cfg names)        protected code regions by design; only strings outside the VM
                                  regions (like the version resource above) remain in plaintext.
- No Discord webhook / C2 URL  → none present in either ASCII or UTF-16LE extraction. If present,
                                  it is inside the VM-protected region and not recoverable
                                  statically.
- No readable disassembly       → entry point and general code are inside .vmp2 (virtualized
  beyond the entry stub           bytecode); a linear disassembler cannot meaningfully decode
                                  VM-dispatched code, as shown in §3.
```

---

## Honest scope of this evidence

- This DLL is VMProtect-protected. Everything reported above comes from parts of the file VMProtect
  does **not** obfuscate by default (import table, PE headers, section layout, version resource) —
  it does not represent a full reverse-engineering of the DLL's logic, and it should not be
  presented as one.
- The interpretation in §5 (ESP rendering, input simulation, etc.) is inferred from *which Win32/
  OpenGL functions are imported*, not from observing the DLL call them — this is standard and
  reasonably reliable capability-fingerprinting practice, but it is inference, not a confirmed
  runtime trace.
- No dynamic analysis (sandbox execution, API call tracing, memory dumping post-VM-unpacking) was
  performed. A full behavioral picture would require running this DLL in an isolated VM with tools
  like Process Monitor / API Monitor / a VMProtect-aware unpacker, which is outside the scope of
  this static pass.
