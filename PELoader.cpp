#include "framework.h"
#include "PELoader.h"

PVOID ReadFileToMemory(const wchar_t* FileName, DWORD& Size)
{
	PVOID Buffer = NULL;
	DWORD FileSize;
	DWORD ReadSize = 0;
	HANDLE hFile = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		return FALSE;
	}
	do{
		FileSize = GetFileSize(hFile, NULL);
		if (FileSize == 0)
		{
			break;
		}
		else
		{
			Buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT, PAGE_READWRITE);
		}
		if (!ReadFile(hFile, Buffer, FileSize, &ReadSize, NULL))
		{
			break;
		}
		Size = FileSize;
		CloseHandle(hFile);
		return Buffer;
	}while(FALSE);
	CloseHandle(hFile);
	return NULL;
}

PVOID PELoader(char* FileData)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)FileData;
	if (IMAGE_DOS_SIGNATURE != dos->e_magic)
	{
		return NULL;
	}
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LONG_PTR)FileData + dos->e_lfanew);
	if (IMAGE_NT_SIGNATURE != nt->Signature)
	{
		return NULL;
	}
#ifdef _WIN64
	if (IMAGE_FILE_MACHINE_AMD64 != nt->FileHeader.Machine)
	{
		return NULL;
	}
#else
	if (IMAGE_FILE_MACHINE_I386 != nt->FileHeader.Machine)
	{
		return NULL;
	}
#endif

	DWORD ImageSize = nt->OptionalHeader.SizeOfImage;
	char* Buffer = (char*)VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Buffer == NULL)
	{
		return NULL;
	}
	ZeroMemory(Buffer, ImageSize);
	
	//节头
	IMAGE_SECTION_HEADER* SectionHeader = (IMAGE_SECTION_HEADER*)((char*)nt + sizeof(IMAGE_NT_HEADERS));
	memcpy(Buffer, FileData, nt->OptionalHeader.SizeOfHeaders);
	WORD SectionNum = nt->FileHeader.NumberOfSections;
	for (WORD i = 0; i < SectionNum; i++, SectionHeader++)
	{
		memcpy(Buffer + SectionHeader->VirtualAddress, FileData + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);
	}
	//重定位表
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)(Buffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		DWORD_PTR Difference = (DWORD_PTR)Buffer - nt->OptionalHeader.ImageBase;
		SIZE_T Size = (SIZE_T)BaseRelocation + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		while (Size > (SIZE_T)BaseRelocation)
		{
			char* Address = Buffer + BaseRelocation->VirtualAddress;
			DWORD Count = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			WORD* RelocationItem = (WORD*)((char*)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < Count; i++)
			{
				WORD Offset = RelocationItem[i] & 0x0fff;
				WORD Type = RelocationItem[i] >> 0x0C;

				if (Type == IMAGE_REL_BASED_ABSOLUTE)
				{
					//无意义
				}
				else if (Type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD32*)(Address + Offset) += Difference;
				}
				else if (Type == IMAGE_REL_BASED_DIR64)
				{
					*(DWORD64*)(Address + Offset) += Difference;
				}
			}
			BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)BaseRelocation + BaseRelocation->SizeOfBlock);
		}
	}
	//导入表
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(Buffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (; ImportDescriptor->Name != NULL; ImportDescriptor++)
		{
			IMAGE_THUNK_DATA* ThunkData = (IMAGE_THUNK_DATA*)(Buffer + ImportDescriptor->FirstThunk);

			char* Name = Buffer + ImportDescriptor->Name;
			HINSTANCE hInstance = LoadLibraryA(Name);
			if (hInstance == NULL)
			{
				VirtualFree(Buffer, 0, MEM_RELEASE);
				return NULL;
			}

			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				FARPROC ProcAddress;
				if (ThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					ProcAddress = GetProcAddress(hInstance, (LPCSTR)(ThunkData->u1.Ordinal & 0x0000ffff));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* ImportByName = (IMAGE_IMPORT_BY_NAME*)(Buffer + ThunkData->u1.Ordinal);
					ProcAddress = GetProcAddress(hInstance, (LPCSTR)ImportByName->Name);
				}

				if (ProcAddress == NULL)
				{
					VirtualFree(Buffer, 0, MEM_RELEASE);
					return NULL;
				}

				ThunkData->u1.Ordinal = (DWORD_PTR)ProcAddress;
			}
		}
	}

	dos = (PIMAGE_DOS_HEADER)Buffer;
	nt = (PIMAGE_NT_HEADERS)((LONG_PTR)Buffer + dos->e_lfanew);
	nt->OptionalHeader.ImageBase = (DWORD_PTR)Buffer;

	return Buffer;
}

BOOL CallDllMain(PVOID hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	auto fnDllMain = (BOOL (WINAPI *)(HMODULE, DWORD, LPVOID)) ((DWORD_PTR)hModule + nt->OptionalHeader.AddressOfEntryPoint);
	return fnDllMain((HMODULE)hModule, ul_reason_for_call, lpReserved);
}

VOID ZeroPE(PVOID hModule)
{
	ZeroMemory(hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew + sizeof(IMAGE_NT_HEADERS));
}



PVOID LoadDll(const wchar_t* FileName, DWORD Reason)
{
	PVOID Address = NULL;
	MEMORY_BASIC_INFORMATION MBI;
	while (VirtualQuery(Address, &MBI, sizeof(MBI)) != 0)
	{
		Address = MBI.BaseAddress;
		if (MBI.State & MEM_COMMIT)
		{
			if (MBI.Protect == PAGE_EXECUTE_READWRITE)
			{
				if (memcmp((char*)Address+8, FileName, wcslen(FileName) * sizeof(wchar_t)) == 0)
				{
					//MessageBoxA(nullptr, "重复注入", "debug", 0);
					return Address;
				}
			}
		}
		Address = PVOID((SIZE_T)Address + MBI.RegionSize);
	}

	PVOID FileData = NULL;
	DWORD FileSize = 0;
	PVOID ImageMemory = NULL;
	if ((FileData = ReadFileToMemory(FileName, FileSize)) && (ImageMemory = PELoader((char*)FileData)))
	{
		ZeroMemory(FileData, FileSize);
		VirtualFree(FileData, 0, MEM_RELEASE);
		CallDllMain(ImageMemory, Reason, (PVOID)FileName);
		CallDllMain(ImageMemory, DLL_PROCESS_ATTACH, NULL);
		ZeroPE(ImageMemory);
		memcpy((char*)ImageMemory+8, FileName, wcslen(FileName) * sizeof(wchar_t));
	}
	return ImageMemory;
}
