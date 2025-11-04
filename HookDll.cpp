// HookDll.cpp (Final - WinAPI logging, reentrancy-safe)
// Build: x64. Link with MinHook (libMinHook.x64.lib or your path)
#include "pch.h"
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include "MinHook/include/MinHook.h"

// #pragma comment(lib, "libMinHook.x64.lib") // 필요 시 주석 해제

typedef BOOL(WINAPI* WriteFile_t)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

static WriteFile_t fpOriginalWriteFile = nullptr;

// --------- Logging state (WinAPI 기반) ----------
static CRITICAL_SECTION g_cs;
static HANDLE g_hLog = INVALID_HANDLE_VALUE;
static const wchar_t* LOG_PATH = L"C:\\Users\\Public\\notepad_writefile_hook.log";

// 훅 재진입 방지용 TLS 플래그 (스레드별)
__declspec(thread) static bool t_in_hook_logging = false;

// 시간 문자열
static std::string time_now_str() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

static std::string hexdump(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    const size_t k = 16;
    for (size_t i = 0; i < len; i += k) {
        oss << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        for (size_t j = 0; j < k; ++j) {
            if (i + j < len)
                oss << std::setw(2) << std::setfill('0') << std::hex << (int)data[i + j] << ' ';
            else
                oss << "   ";
        }
        oss << " | ";
        for (size_t j = 0; j < k && i + j < len; ++j) {
            unsigned char c = data[i + j];
            oss << ((c >= 0x20 && c <= 0x7e) ? (char)c : '.');
        }
        oss << '\n';
    }
    return oss.str();
}

// WinAPI 기반 안전 로그 (Hook 안에서만 호출됨)
static void safe_log(const std::string& line) {
    EnterCriticalSection(&g_cs);

    if (g_hLog == INVALID_HANDLE_VALUE) {
        g_hLog = CreateFileW(
            LOG_PATH,
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (g_hLog != INVALID_HANDLE_VALUE) {
            // append로 열었지만 명시적으로 파일 포인터를 끝으로 이동
            SetFilePointer(g_hLog, 0, nullptr, FILE_END);
        }
    }

    if (g_hLog != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        // CR/LF 포함해 한 번에 기록
        std::string out = line;
        out.append("\r\n");
        // WriteFile은 훅 대상이지만, 재진입 플래그로 훅 내부에서 원본 호출로 우회됨
        t_in_hook_logging = true;
        fpOriginalWriteFile(g_hLog, out.data(), (DWORD)out.size(), &written, nullptr);
        t_in_hook_logging = false;
    }

    LeaveCriticalSection(&g_cs);
}

static void log_writefile_info(HANDLE hFile, const unsigned char* buf, DWORD len) {
    std::ostringstream oss;
    oss << "[" << time_now_str() << "] WriteFile called. Handle=0x"
        << std::hex << (uintptr_t)hFile
        << std::dec << " size=" << len << "\n";
    oss << hexdump(buf, len);
    safe_log(oss.str());
}

// --------- Hook function ----------
BOOL WINAPI HookedWriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    // 재진입(로그 쓰는 중)일 때는 무조건 원본으로 바로 위임 (무한 재귀 방지)
    if (t_in_hook_logging) {
        return fpOriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
            lpNumberOfBytesWritten, lpOverlapped);
    }

    // 로깅 (최대 1KB만)
    const DWORD MAX_LOG_BYTES = 1024;
    DWORD toLog = nNumberOfBytesToWrite;
    if (toLog > MAX_LOG_BYTES) toLog = MAX_LOG_BYTES;

    if (lpBuffer && toLog > 0) {
        // 로그 중에 다시 WriteFile을 호출하므로 재진입 플래그 켜고/끄는 건 safe_log 내부에서 처리
        log_writefile_info(hFile, (const unsigned char*)lpBuffer, toLog);
    }
    else {
        safe_log("[HookedWriteFile] empty buffer or size 0");
    }

    // (옵션) 데이터 변조 테스트를 하려면 아래 블록을 사용
    /*
    std::vector<unsigned char> modbuf((const unsigned char*)lpBuffer,
                                      (const unsigned char*)lpBuffer + nNumberOfBytesToWrite);
    const char* tail = "\n[HOOKED_BY_LAB]";
    modbuf.insert(modbuf.end(), tail, tail + strlen(tail));
    return fpOriginalWriteFile(hFile, modbuf.data(), (DWORD)modbuf.size(),
                               lpNumberOfBytesWritten, lpOverlapped);
    */

    return fpOriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
        lpNumberOfBytesWritten, lpOverlapped);
}

// --------- Hook install / remove ----------
static bool install_hooks() {
    if (MH_Initialize() != MH_OK) return false;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;

    FARPROC pWriteFile = GetProcAddress(hKernel32, "WriteFile");
    if (!pWriteFile) return false;

    if (MH_CreateHook(pWriteFile, &HookedWriteFile,
        reinterpret_cast<LPVOID*>(&fpOriginalWriteFile)) != MH_OK)
        return false;

    if (MH_EnableHook(pWriteFile) != MH_OK) return false;

    safe_log("[HookDll] hooks installed");
    return true;
}

static void remove_hooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    EnterCriticalSection(&g_cs);
    if (g_hLog != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hLog);
        g_hLog = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_cs);
}

// --------- DllMain ----------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_cs);
        // DllMain에서 무거운 작업 금지 → 별도 스레드에서 훅 설치
        CreateThread(nullptr, 0,
            (LPTHREAD_START_ROUTINE)+[](LPVOID)->DWORD {
                if (!install_hooks()) {
                    safe_log("[HookDll] install_hooks failed");
                }
                return 0;
            },
            nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        remove_hooks();
        DeleteCriticalSection(&g_cs);
        break;
    }
    return TRUE;
}
