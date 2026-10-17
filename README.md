# streamproof-unhide

Usermode WDA scanner and remover for Windows. It enumerates all top-level windows, identifies those marked with `WDA_EXCLUDEFROMCAPTURE` (invisible to any capture API), and clears the flag by injecting a minimal x64 stub into the owning process via `CreateRemoteThread`.

Not an antivirus. Not a kernel tool. Designed for forensic screensharing analysis on FiveM and similar environments with Administrator rights.

---

## What it does

streamproof-unhide calls `EnumWindows` and reads the display affinity of every window with `GetWindowDisplayAffinity`. For each protected hit it injects a 35-byte shellcode stub that calls `SetWindowDisplayAffinity(hwnd, WDA_NONE)` from inside the owning process, verifies the result, and brings the window to the foreground centered on screen.

Each detection is anchored to:
- Process name
- PID
- HWND
- Affinity value before and after removal

---

## How the removal works

`SetWindowDisplayAffinity` can only be called by the owning thread. To clear the flag from an external process, the tool allocates executable memory in the target via `VirtualAllocEx`, writes a 35-byte x64 stub, and runs it with `CreateRemoteThread`. The stub calls `SetWindowDisplayAffinity(hwnd, 0)` directly. `USER32.dll` maps at the same virtual address in all processes on the same boot, so no fixup is needed.

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

## Limitations

- Requires `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` on the target. Will fail against PPL-protected or handle-protected processes.
- x64 only. Will not work correctly against 32-bit (WOW64) targets.
- Does not persist. If the target calls `SetWindowDisplayAffinity` again, the flag returns.

---

## License

MIT
