#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <vector>
#include <set>

static bool BringToFrontCentered(HWND hwnd, bool alwaysOnTop = false, HWND monAnchor = nullptr) {
    if (!IsWindow(hwnd)) return false;
    if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);

    HMONITOR mon = MonitorFromWindow(monAnchor ? monAnchor : hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{ sizeof(mi) };
    GetMonitorInfo(mon, &mi);
    RECT r;
    GetWindowRect(hwnd, &r);
    int w = r.right - r.left, h = r.bottom - r.top;
    int x = mi.rcWork.left + ((mi.rcWork.right  - mi.rcWork.left) - w) / 2;
    int y = mi.rcWork.top  + ((mi.rcWork.bottom - mi.rcWork.top)  - h) / 2;

    SetWindowPos(hwnd, alwaysOnTop ? HWND_TOPMOST : HWND_TOP, x, y, 0, 0,
                 SWP_NOSIZE | SWP_SHOWWINDOW);

    HWND fg = GetForegroundWindow();
    DWORD fgThread = GetWindowThreadProcessId(fg, nullptr);
    DWORD myThread = GetCurrentThreadId();
    if (fg && fgThread != myThread) AttachThreadInput(myThread, fgThread, TRUE);
    BringWindowToTop(hwnd);
    bool ok = SetForegroundWindow(hwnd) != FALSE;
    SetFocus(hwnd);
    if (fg && fgThread != myThread) AttachThreadInput(myThread, fgThread, FALSE);
    return ok;
}

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

struct WdaHit {
    HWND    hwnd;
    DWORD   pid;
    DWORD   affinity;
    char    title[256];
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

typedef NTSTATUS (NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, LPVOID, HANDLE,
    LPTHREAD_START_ROUTINE, LPVOID, ULONG,
    SIZE_T, SIZE_T, SIZE_T, LPVOID);

typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL   (WINAPI* pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

static bool ClearWda(HWND hwnd, DWORD pid) {
    char s_u32[]   = { 'u','s','e','r','3','2','.','d','l','l',0 };
    char s_fn[]    = { 'S','e','t','W','i','n','d','o','w','D','i','s','p','l','a','y',
                       'A','f','f','i','n','i','t','y',0 };
    char s_k32[]   = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    char s_ntd[]   = { 'n','t','d','l','l','.','d','l','l',0 };
    char s_nte[]   = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
    char s_vae[]   = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0 };
    char s_wpm[]   = { 'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0 };
    char s_vpe[]   = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','E','x',0 };
    char s_vfe[]   = { 'V','i','r','t','u','a','l','F','r','e','e','E','x',0 };

    HMODULE u32 = GetModuleHandleA(s_u32);
    if (!u32) u32 = LoadLibraryA(s_u32);
    FARPROC fn = GetProcAddress(u32, s_fn);
    if (!fn) return false;

    HMODULE k32  = GetModuleHandleA(s_k32);
    HMODULE ntdl = GetModuleHandleA(s_ntd);

    auto _VirtualAllocEx     = (pVirtualAllocEx)    GetProcAddress(k32,  s_vae);
    auto _WriteProcessMemory = (pWriteProcessMemory) GetProcAddress(k32,  s_wpm);
    auto _VirtualProtectEx   = (pVirtualProtectEx)   GetProcAddress(k32,  s_vpe);
    auto _VirtualFreeEx      = (pVirtualFreeEx)      GetProcAddress(k32,  s_vfe);
    auto _NtCreateThreadEx   = (pNtCreateThreadEx)   GetProcAddress(ntdl, s_nte);

    if (!_VirtualAllocEx || !_WriteProcessMemory || !_VirtualProtectEx ||
        !_VirtualFreeEx  || !_NtCreateThreadEx) return false;

#define SC_KEY 0xAB
    unsigned char sc_enc[] = {
        0x48^SC_KEY, 0xB9^SC_KEY, 0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,
        0x33^SC_KEY, 0xD2^SC_KEY,
        0x48^SC_KEY, 0x83^SC_KEY, 0xEC^SC_KEY, 0x28^SC_KEY,
        0x48^SC_KEY, 0xB8^SC_KEY, 0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,0^SC_KEY,
        0xFF^SC_KEY, 0xD0^SC_KEY,
        0x48^SC_KEY, 0x83^SC_KEY, 0xC4^SC_KEY, 0x28^SC_KEY,
        0x33^SC_KEY, 0xC0^SC_KEY,
        0xC3^SC_KEY
    };
    unsigned char sc[35];
    for (int i = 0; i < 35; i++) sc[i] = sc_enc[i] ^ SC_KEY;
#undef SC_KEY

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

    LPVOID mem = _VirtualAllocEx(proc, nullptr, sizeof(sc),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(proc); return false; }

    SIZE_T written = 0;
    _WriteProcessMemory(proc, mem, sc, sizeof(sc), &written);

    DWORD old = 0;
    _VirtualProtectEx(proc, mem, sizeof(sc), PAGE_EXECUTE_READ, &old);

    HANDLE thr = nullptr;
    _NtCreateThreadEx(&thr, GENERIC_ALL, nullptr, proc,
                      (LPTHREAD_START_ROUTINE)mem, nullptr, 0, 0, 0, 0, nullptr);
    if (!thr) {
        printf("  thread creation failed\n");
        _VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    WaitForSingleObject(thr, 3000);
    _VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
    CloseHandle(thr);
    CloseHandle(proc);
    return true;
}

int main() {
    HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(con, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("streamproof-unhide");
    SetConsoleTextAttribute(con, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  by vipper. https://github.com/viipperr\n\n");
    printf("Scanning continuously. Ctrl+C to exit.\n\n");

    std::set<HWND> cleared;

    for (DWORD cycle = 0; ; cycle++) {
        std::vector<WdaHit> hits;
        EnumWindows(EnumCb, reinterpret_cast<LPARAM>(&hits));

        for (auto& h : hits)
            if (cleared.count(h.hwnd))
                cleared.erase(h.hwnd);  // WDA re-applied, process again

        for (auto& h : hits) {
            if (cleared.count(h.hwnd)) continue;

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

            if (after == 0) {
                cleared.insert(h.hwnd);
                BringToFrontCentered(h.hwnd, true, GetConsoleWindow());
            }
        }

        for (auto it = cleared.begin(); it != cleared.end(); )
            it = IsWindow(*it) ? std::next(it) : cleared.erase(it);

        printf("\r[cycle %lu | cleared %zu]   ", cycle, cleared.size());
        fflush(stdout);

        Sleep(500);
    }
}
