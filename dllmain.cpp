// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"
#include "PELoader.h"

#pragma comment(linker, "/SECTION:.text,ERW")
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")

#pragma comment(linker, "/ENTRY:EntryPoint")


DWORD WINAPI InitPlugin(LPVOID lpThreadParameter);


// DllMain
BOOL APIENTRY EntryPoint(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	static BOOL IsManualMappingInjection = FALSE;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		api.Init();
		wchar_t FilePath[MAX_PATH];
		if (!IsManualMappingInjection)
		{
			if (api.GetModuleFileNameW(hModule, FilePath, MAX_PATH) != 0)
			{
				LoadDll(FilePath, -1);
				return FALSE;
			}
		}
		wchar_t* FileName;
		api.GetModuleFileNameW(nullptr, FilePath, MAX_PATH);
		FileName = my_wcsrchr(FilePath, '\\');
		if (FileName)
		{
			FileName++;
			if (my_wcsnicmp(FileName, XorString(L"GameApp.exe"), 12) == 0)
			{
				HANDLE hThread = api.CreateThread(NULL, 0, InitPlugin, NULL, 0, NULL);
				if (hThread)
				{
					api.CloseHandle(hThread);
				}
				break;
			}
		}
		return FALSE;
	}
	case DLL_PROCESS_DETACH:
		break;
	case -1:
		IsManualMappingInjection = TRUE;
		break;
	}
	return TRUE;
}
