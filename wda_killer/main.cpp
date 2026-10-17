#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <vector>

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

struct WdaHit {
    HWND  hwnd;
    DWORD pid;
    DWORD affinity;
    char  title[256];
    wchar_t exename[260];
};

static bool GetExeName(DWORD pid, wchar_t* out, size_t n) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcsncpy_s(out, n, pe.szExeFile, _TRUNCATE);
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static BOOL CALLBACK EnumCb(HWND hwnd, LPARAM lp) {
    DWORD aff = 0;
    if (!GetWindowDisplayAffinity(hwnd, &aff) || aff == 0)
        return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid || pid == GetCurrentProcessId() || pid == 4)
        return TRUE;
    WdaHit h{};
    h.hwnd     = hwnd;
    h.pid      = pid;
    h.affinity = aff;
    GetWindowTextA(hwnd, h.title, sizeof(h.title));
    GetExeName(pid, h.exename, 260);
    reinterpret_cast<std::vector<WdaHit>*>(lp)->push_back(h);
    return TRUE;
}

// Injects shellcode into pid that calls SetWindowDisplayAffinity(hwnd, WDA_NONE).
// USER32.dll maps at the same VA in every process on the same boot — no relocation needed.
static bool ClearWda(HWND hwnd, DWORD pid) {
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!u32) u32 = LoadLibraryA("user32.dll");
    FARPROC fn = GetProcAddress(u32, "SetWindowDisplayAffinity");
    if (!fn) return false;

    // x64 shellcode:
    //   mov rcx, <hwnd>        ; 48 B9 [8]
    //   xor edx, edx           ; 33 D2          (WDA_NONE = 0)
    //   sub rsp, 28h           ; 48 83 EC 28    (shadow space + align)
    //   mov rax, <fn>          ; 48 B8 [8]
    //   call rax               ; FF D0
    //   add rsp, 28h           ; 48 83 C4 28
    //   xor eax, eax           ; 33 C0
    //   ret                    ; C3
    unsigned char sc[35] = {
        0x48, 0xB9, 0,0,0,0,0,0,0,0,   // [0..9]
        0x33, 0xD2,                      // [10,11]
        0x48, 0x83, 0xEC, 0x28,          // [12..15]
        0x48, 0xB8, 0,0,0,0,0,0,0,0,   // [16..25]
        0xFF, 0xD0,                      // [26,27]
        0x48, 0x83, 0xC4, 0x28,          // [28..31]
        0x33, 0xC0,                      // [32,33]
        0xC3                             // [34]
    };

    ULONG64 hwnd64 = (ULONG64)(ULONG_PTR)hwnd;
    ULONG64 fn64   = (ULONG64)(ULONG_PTR)fn;
    memcpy(sc + 2,  &hwnd64, 8);
    memcpy(sc + 18, &fn64,   8);

    HANDLE proc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!proc) {
        printf("  OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    LPVOID mem = VirtualAllocEx(proc, nullptr, sizeof(sc),
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        CloseHandle(proc);
        return false;
    }

    SIZE_T written = 0;
    WriteProcessMemory(proc, mem, sc, sizeof(sc), &written);

    HANDLE thr = CreateRemoteThread(proc, nullptr, 0,
                                    (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    if (!thr) {
        printf("  CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    WaitForSingleObject(thr, 3000);
    VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
    CloseHandle(thr);
    CloseHandle(proc);
    return true;
}

int main() {
    AllocConsole();
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);

    printf("=== WDA Killer ===\n\n");

    std::vector<WdaHit> hits;
    EnumWindows(EnumCb, reinterpret_cast<LPARAM>(&hits));

    if (hits.empty()) {
        printf("No WDA-protected windows found.\n");
        system("pause");
        return 0;
    }

    printf("Found %zu protected window(s):\n\n", hits.size());

    for (auto& h : hits) {
        printf("HWND: %p  PID: %lu  affinity: 0x%X\n",
               (void*)h.hwnd, h.pid, h.affinity);
        printf("  exe:   %ls\n", h.exename);
        printf("  title: %s\n", h.title[0] ? h.title : "(none)");
        printf("  removing WDA... ");

        bool ok = ClearWda(h.hwnd, h.pid);
        if (!ok) {
            printf("FAIL\n\n");
            continue;
        }

        Sleep(150);
        DWORD after = 0;
        GetWindowDisplayAffinity(h.hwnd, &after);
        printf("OK  ->  affinity after: 0x%X %s\n\n",
               after, after == 0 ? "(cleared)" : "(still set?)");
    }

    system("pause");
    return 0;
}
