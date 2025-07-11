#pragma once

struct ApiFunctionPointers {
	bool Init();
	// kernel32
	HMODULE(WINAPI* LoadLibraryA)(LPCSTR lpLibFileName);
	FARPROC(WINAPI* GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	HANDLE(WINAPI* CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
	BOOL(WINAPI* GetFileSizeEx)(HANDLE hFile, PLARGE_INTEGER lpFileSize);
	BOOL(WINAPI* ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
	BOOL(WINAPI* CloseHandle)(HANDLE hObject);
	LPVOID(WINAPI* VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	BOOL(WINAPI* VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
	SIZE_T(WINAPI* VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
	DWORD(WINAPI* GetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	HANDLE(WINAPI* CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
	HMODULE(WINAPI* GetModuleHandleW)(LPCWSTR lpModuleName);
	DWORD(WINAPI* GetCurrentProcessId)(VOID);
	VOID(WINAPI* Sleep)(DWORD dwMilliseconds);
	BOOL(WINAPI* VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	// user32
	DWORD(WINAPI* GetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);
	HWND(WINAPI* FindWindowExW)(HWND hWndParent, HWND hWndChildAfter, LPCWSTR lpszClass, LPCWSTR lpszWindow);
	UINT_PTR(WINAPI* SetTimer)(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);
	int(WINAPIV* wsprintfW)(LPWSTR, LPCWSTR, ...);
	int(WINAPI* MessageBoxTimeoutW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType, WORD wLanguageId, DWORD dwMilliseconds); //未公开

	// CRT
	void*(__cdecl* malloc)(size_t size);
	void(__cdecl* free)(void* block);
	void*(__cdecl* memset)(void* dst, int val, size_t size);
	int(__cdecl* memcmp)(void const* buf1, void const* buf2, size_t size);
	size_t(__cdecl* wcslen)(wchar_t const* string);
};
extern struct ApiFunctionPointers api;


inline void* my_memcpy(void* d, const void* s, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		((char*)d)[i] = ((char*)s)[i];
	}
	return d;
}

inline wchar_t* my_wcsrchr(const wchar_t* str, wchar_t ch) {
	const wchar_t* p = str;
	while (*p != L'\0') {
		p++;
	}
	while (p > str) {
		p--;
		if (*p == ch) {
			return (wchar_t*)p;
		}
	}
	return nullptr;
}

inline int my_wcsnicmp(const wchar_t* s1, const wchar_t* s2, size_t n)
{
	wchar_t c1 = 0, c2 = 0;
	for (size_t i = 0; i < n; i++)
	{
		c1 = s1[i];
		c2 = s2[i];
		// 终止符
		if (c1 == 0)
			break;
		// 转换为小写
		if (c1 >= 'A' && c1 <= 'Z')
			c1 += 32;
		if (c2 >= 'A' && c2 <= 'Z')
			c2 += 32;
		// 不相等
		if (c1 != c2)
			break;
	}
	// 返回差值
	return (c1 - c2);
}

inline int my_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2 && *s1 == *s2)
    {
        s1++;
        s2++;
    }
    return *s1 - *s2;
}
