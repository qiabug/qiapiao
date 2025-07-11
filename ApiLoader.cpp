#include "framework.h"
#include "ApiLoader.h"
#include "PebWalking.h"

struct ApiFunctionPointers api = {};

bool ApiFunctionPointers::Init()
{
	HMODULE kernel32 = (HMODULE)GetModuleBase(L"kernel32.dll");
	*(void**)&api.GetProcAddress = GetProcedureAddress(kernel32, "GetProcAddress");
	*(void**)&api.LoadLibraryA = api.GetProcAddress(kernel32, "LoadLibraryA");
	*(void**)&api.CreateFileW = api.GetProcAddress(kernel32, "CreateFileW");
	*(void**)&api.GetFileSizeEx = api.GetProcAddress(kernel32, "GetFileSizeEx");
	*(void**)&api.ReadFile = api.GetProcAddress(kernel32, "ReadFile");
	*(void**)&api.CloseHandle = api.GetProcAddress(kernel32, "CloseHandle");
	*(void**)&api.VirtualAlloc = api.GetProcAddress(kernel32, "VirtualAlloc");
	*(void**)&api.VirtualFree = api.GetProcAddress(kernel32, "VirtualFree");
	*(void**)&api.VirtualQuery = api.GetProcAddress(kernel32, "VirtualQuery");
	*(void**)&api.GetModuleFileNameW = api.GetProcAddress(kernel32, "GetModuleFileNameW");
	*(void**)&api.CreateThread = api.GetProcAddress(kernel32, "CreateThread");
	*(void**)&api.GetModuleHandleW = api.GetProcAddress(kernel32, "GetModuleHandleW");
	*(void**)&api.GetCurrentProcessId = api.GetProcAddress(kernel32, "GetCurrentProcessId");
	*(void**)&api.Sleep = api.GetProcAddress(kernel32, "Sleep");
	*(void**)&api.VirtualProtect = api.GetProcAddress(kernel32, "VirtualProtect");
	
	HMODULE user32 = api.LoadLibraryA("user32.dll");
	*(void**)&api.GetWindowThreadProcessId = api.GetProcAddress(user32, "GetWindowThreadProcessId");
	*(void**)&api.FindWindowExW = api.GetProcAddress(user32, "FindWindowExW");
	*(void**)&api.SetTimer = api.GetProcAddress(user32, "SetTimer");
	*(void**)&api.wsprintfW = api.GetProcAddress(user32, "wsprintfW");
	*(void**)&api.MessageBoxTimeoutW = api.GetProcAddress(user32, "MessageBoxTimeoutW");

	HMODULE ucrtbase = api.LoadLibraryA("ucrtbase.dll");
	*(void**)&api.malloc = api.GetProcAddress(ucrtbase, "malloc");
	*(void**)&api.free = api.GetProcAddress(ucrtbase, "free");
	*(void**)&api.memset = api.GetProcAddress(ucrtbase, "memset");
	*(void**)&api.memcmp = api.GetProcAddress(ucrtbase, "memcmp");
	*(void**)&api.wcslen = api.GetProcAddress(ucrtbase, "wcslen");

	return true;
}
