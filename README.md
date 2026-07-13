# lze-analysis

Static analysis of an internal cheat targeting CraftRise, consisting of two components: a
.NET loader/updater (`Laze_Loader.exe`) and a VMProtect-protected native payload DLL (`Laze.dll`).
Publicly distributed as "Laze Free" via `github.com/aaleaf/laze` and `github.com/aaleaf/Laze`.

**Code Distribution & Ethics Disclaimer:** To preserve competitive integrity and avoid facilitating
cheat development, the executable binaries and any reconstructed or decompiled source code are
strictly excluded from this repository. The import tables, string dumps, and disassembly excerpts
provided are limited to structural analysis and architectural signatures, intended solely for
defensive research and anti-cheat detection purposes.

## Summary

| | Laze_Loader.exe | Laze.dll |
|---|---|---|
| Type | .NET Framework 4.6.1 console app | Native x86-64 DLL, GUI subsystem |
| Size | 120,832 bytes | 1,148,416 bytes |
| Protection | None (fully readable metadata) | **VMProtect** (`.vmp0`/`.vmp1`/`.vmp2` sections) |
| Role | Downloader + `LoadLibraryA`/`CreateRemoteThread` injector | Payload: ESP overlay + input simulation |
| SHA256 | `c0122c25beb71df212695fb968c2fd6cf66039d8841e3245ad49475e0a44d590` | `6ed0674e02ef61821a4d458c4a7d97258715efaaa1b672a81b22073a42f4868b` |

**Target identification:** the loader searches running processes by main window title, matching
`craftrise-x64` and `sonoyuncuclient`.

**Distribution:** the loader downloads the current payload from
`https://github.com/aaleaf/Files/raw/main/Bin/laze.dll` on every run (after a version check
against `https://raw.githubusercontent.com/aaleaf/Files/main/data`), verifies it via SHA-1, then
injects it into the target process using the classic `VirtualAllocEx` → `WriteProcessMemory` →
`CreateRemoteThread(LoadLibraryA, ...)` sequence.

**Payload capability (inferred from Laze.dll's import table — see DLL evidence doc for full
reasoning):** OpenGL immediate-mode rendering functions (`glVertex3f`, `glColor4f`, `glBegin`/
`glEnd`, etc.) consistent with ESP/wallhack overlay rendering, combined with input simulation
(`SendInput`, `keybd_event`, `SetCursorPos`) and input polling (`GetAsyncKeyState`) consistent with
aim/movement assistance.

## Contents

- [`LOADER_STATIC_ANALYSIS_EVIDENCE.md`](./LOADER_STATIC_ANALYSIS_EVIDENCE.md) — full PE header,
  .NET metadata (method names, P/Invoke targets), version resource, and every network
  endpoint/target string extracted from `Laze_Loader.exe`, plus a reconstructed step-by-step
  execution flow.
- [`DLL_STATIC_ANALYSIS_EVIDENCE.md`](./DLL_STATIC_ANALYSIS_EVIDENCE.md) — full PE header, section
  layout showing the VMProtect signature, complete categorized import table, and capability
  analysis for `Laze.dll`.

## Scope & Limitations

- This is static analysis only. Neither binary was executed; no network requests were made to the
  URLs referenced above; no dynamic/behavioral testing against a live CraftRise client was
  performed.
- `Laze.dll` is VMProtect-protected, which conceals its actual code and most string literals.
  Findings for this file are based on its import table and version resource — the parts VMProtect
  does not obfuscate — and are explicitly framed as capability inference, not confirmed behavior.
- Every claim in the two evidence documents is traceable to a specific raw tool output; where a
  conclusion is inferred rather than directly observed, this is stated explicitly in that
  document's "Honest scope" section.
