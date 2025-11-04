#include <windows.h>
#include <iostream>
#include <string>

bool InjectDLL(DWORD pid, const std::wstring& dllPath) {
	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!hProc) {
		std::wcerr << L"OpenProcess failed: " << GetLastError() << L"\n";
		return false;
	}

	size_t size = (dllPath.size() + 1) * sizeof(wchar_t);
	LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
	if (!remoteMem) {
		std::wcerr << L"VirtualAllocEx failed: " << GetLastError() << L"\n";
		CloseHandle(hProc);
		return false;
	}

	if (!WriteProcessMemory(hProc, remoteMem, dllPath.c_str(), size, nullptr)) {
		std::wcerr << L"WriteProcessMemory failed: " << GetLastError() << L"\n";
		VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	LPTHREAD_START_ROUTINE pfnLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	if (!pfnLoadLibraryW) {
		std::wcerr << L"GetProcAddress LoadLibrary failed\n";
		VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pfnLoadLibraryW, remoteMem, 0, nullptr);
	if (!hThread) {
		std::wcerr << L"CreateRemoteThread failed: " << GetLastError() << L"\n";
		VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
	CloseHandle(hProc);
	return true;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 3) {
		std::wcout << L"Usage: injector <PID> <full_path_to_dll>\n";
		return 1;
	}
	DWORD pid = std::stoul(argv[1]);
	std::wstring dllPath = argv[2];
	if (InjectDLL(pid, dllPath)) {
		std::wcout << L"Injection succeeded\n";
	}
	else {
		std::wcout << L"Injection failed\n";
	}
	return 0;
}