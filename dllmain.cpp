// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"
#include "ConstEncrypt.h"
#include "PELoader.h"

BOOL IsManualMapInjection = FALSE;

DWORD WINAPI InitPlugin(LPVOID lpThreadParameter);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (IsManualMapInjection)
		{
			HANDLE hThread = CreateThread(NULL, 0, InitPlugin, NULL, 0, NULL);
			if (hThread)
			{
				CloseHandle(hThread);
			}
			break;
		}
		wchar_t FilePath[MAX_PATH];
		wchar_t* FileName;
		GetModuleFileNameW(nullptr, FilePath, MAX_PATH);
		FileName = wcsrchr(FilePath, '\\');
		if (FileName)
		{
			FileName++;
			if (_wcsicmp(FileName, XorString(L"GameApp.exe")) == 0)
			{
				if (GetModuleFileNameW(hModule, FilePath, MAX_PATH) != 0)
				{
					LoadDll(FilePath, -1);
				}
			}
		}
		return FALSE;
	}
	case DLL_PROCESS_DETACH:
		break;
	case -1:
		IsManualMapInjection = TRUE;
		break;
	}
	return TRUE;
}
