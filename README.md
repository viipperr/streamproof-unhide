# streamproof-unhide

Detects windows protected with `WDA_EXCLUDEFROMCAPTURE` (SetWindowDisplayAffinity) and removes the flag from them by injecting a minimal shellcode stub into the owning process.

Useful for forensic analysis, anti-cheat research, and capture transparency auditing.

---

## How it works

`SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE (0x11)` marks a window as invisible to screen capture APIs (DXGI, BitBlt, NvFBC, OBS, etc.). The flag is enforced by win32k — only the owning thread/process can set or clear it.

**Detection** is trivial: `GetWindowDisplayAffinity` works cross-process. Any caller can read the flag.

**Removal** requires running `SetWindowDisplayAffinity(hwnd, WDA_NONE)` from *inside* the owning process. This tool does that via a 35-byte x64 shellcode stub injected with `CreateRemoteThread`.

```
mov rcx, <hwnd>           ; target window handle
xor edx, edx              ; WDA_NONE = 0
sub rsp, 28h              ; shadow space + alignment
mov rax, <SetWindowDisplayAffinity>
call rax
add rsp, 28h
xor eax, eax
ret
```

`USER32.dll` maps at the same virtual address in all processes on the same boot, so the function pointer resolved locally is valid in the remote process.

---

## Components

| Binary | Description |
|---|---|
| `wda_killer.exe` | Enumerates all windows, finds those with affinity != 0, injects the stub and verifies the flag was cleared |
| `wda_test.exe` | Creates a test window with `WDA_EXCLUDEFROMCAPTURE` active — use it to verify detection and removal |

---

## Build

Requires MSVC (Visual Studio 2019+ or Build Tools). Run from a **x64 Developer Command Prompt**:

```bat
cl /nologo /O2 /std:c++17 /EHsc /Fe:wda_test.exe wda_test\main.cpp user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS
cl /nologo /O2 /std:c++17 /EHsc /Fe:wda_killer.exe wda_killer\main.cpp user32.lib
```

Or use the included `build.bat`.

---

## Usage

1. Run `wda_test.exe` to create a protected test window (verify it disappears from OBS/capture).
2. Run `wda_killer.exe` **as Administrator** — it will find the window, inject the stub, and report the affinity before and after.

```
=== WDA Killer ===

Found 1 protected window(s):

HWND: 0x000A0B2C  PID: 18440  affinity: 0x11
  exe:   wda_test.exe
  title: WDA Test [protected]
  removing WDA... OK  ->  affinity after: 0x0 (cleared)
```

---

## Notes

- Requires `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` on the target — run as admin or with SeDebugPrivilege.
- Does not persist. The flag returns if the target process calls `SetWindowDisplayAffinity` again.
- Tested on Windows 10 22H2 / Windows 11 23H2 x64.

---

## License

MIT
