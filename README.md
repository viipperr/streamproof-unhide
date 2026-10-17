# streamproof-unhide

Scans all windows on the system, detects those protected with `WDA_EXCLUDEFROMCAPTURE` (SetWindowDisplayAffinity), removes the flag, and brings the window to the foreground centered on screen.

Useful for forensic screensharing analysis and capture transparency auditing.

---

## How it works

`SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE (0x11)` marks a window as invisible to any screen capture API (DXGI, BitBlt, NvFBC, OBS, etc.). The flag is enforced by win32k and can only be set or cleared by the owning thread.

**Detection:** `GetWindowDisplayAffinity` works cross-process. Any caller can read the flag on any window.

**Removal:** `SetWindowDisplayAffinity(hwnd, WDA_NONE)` must be called from inside the owning process. This tool allocates a 35-byte x64 shellcode stub in the target process via `VirtualAllocEx`, writes it with `WriteProcessMemory`, and executes it with `CreateRemoteThread`. The stub calls `SetWindowDisplayAffinity(hwnd, 0)` directly.

`USER32.dll` maps at the same virtual address in all processes on the same boot, so the function pointer resolved in our process is valid in the remote process without any fixup.

After clearing the flag, the tool verifies the result with a second `GetWindowDisplayAffinity` call, then centers the window on screen and sets it as topmost.

```
mov rcx, <hwnd>
xor edx, edx
sub rsp, 28h
mov rax, <SetWindowDisplayAffinity>
call rax
add rsp, 28h
xor eax, eax
ret
```

---

## Usage

Run `wda_killer.exe` as Administrator. Windows will prompt UAC automatically.

```
streamproof-unhide  by vipper. https://github.com/viipperr

Found 1 protected window(s):

HWND: 0x000A0B2C  PID: 18440  affinity: 0x11
  exe:   example.exe
  title: Example Window
  removing WDA... OK  ->  affinity after: 0x0 (cleared)
```

---

## Limitations

- Requires `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` on the target. Will fail against PPL-protected or handle-protected processes.
- x64 only. Will not work correctly if the target process is 32-bit (WOW64).
- Does not persist. If the target process calls `SetWindowDisplayAffinity` again, the flag returns.

---

## Build

Requires MSVC (Visual Studio 2019+ or Build Tools), x64 Developer Command Prompt.

```bat
cl /nologo /O2 /std:c++17 /EHsc /Fe:wda_killer.exe wda_killer\main.cpp user32.lib /link /MANIFEST:NO
mt.exe -nologo -manifest wda_killer\app.manifest -outputresource:wda_killer.exe;#1
```

---

## License

MIT
