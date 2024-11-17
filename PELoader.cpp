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
	do {
		FileSize = GetFileSize(hFile, NULL);
		if (FileSize == 0) {
			break;
		}
		else {
			Buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT, PAGE_READWRITE);
		}
		if (!ReadFile(hFile, Buffer, FileSize, &ReadSize, NULL)) {
			VirtualFree(Buffer, 0, MEM_RELEASE);
			Buffer = NULL;
			break;
		}
		Size = FileSize;
	} while (FALSE);
	CloseHandle(hFile);
	return Buffer;
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

	DWORD imageSize = nt->OptionalHeader.SizeOfImage;
	char* imageBuffer = (char*)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (imageBuffer == NULL)
	{
		return NULL;
	}
	ZeroMemory(imageBuffer, imageSize);
	
	//Section
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((char*)nt + sizeof(IMAGE_NT_HEADERS));
	memcpy(imageBuffer, FileData, nt->OptionalHeader.SizeOfHeaders);
	WORD sectionNumber = nt->FileHeader.NumberOfSections;
	for (WORD i = 0; i < sectionNumber; i++)
	{
		memcpy(imageBuffer + sections[i].VirtualAddress, FileData + sections[i].PointerToRawData, sections[i].SizeOfRawData);
	}

	//BaseReloc
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)(imageBuffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		DWORD_PTR Difference = (DWORD_PTR)imageBuffer - nt->OptionalHeader.ImageBase;
		SIZE_T Size = (SIZE_T)BaseRelocation + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		while (Size > (SIZE_T)BaseRelocation)
		{
			char* Address = imageBuffer + BaseRelocation->VirtualAddress;
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
#ifndef _WIN64
				else if (Type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD32*)(Address + Offset) += Difference;
				}
#else
				else if (Type == IMAGE_REL_BASED_DIR64)
				{
					*(DWORD64*)(Address + Offset) += Difference;
				}
#endif
			}
			BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)BaseRelocation + BaseRelocation->SizeOfBlock);
		}
	}

	//Import
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(imageBuffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (; ImportDescriptor->Name; ImportDescriptor++)
		{
			IMAGE_THUNK_DATA* ThunkData = (IMAGE_THUNK_DATA*)(imageBuffer + ImportDescriptor->FirstThunk);

			char* name = imageBuffer + ImportDescriptor->Name;
			HINSTANCE hInstance = LoadLibraryA(name);
			if (hInstance == NULL)
			{
				VirtualFree(imageBuffer, 0, MEM_RELEASE);
				return NULL;
			}

			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				FARPROC address;
				if (ThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					DWORD_PTR ordinal = IMAGE_ORDINAL(ThunkData->u1.Ordinal);
					address = GetProcAddress(hInstance, (LPCSTR)ordinal);
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(imageBuffer + ThunkData->u1.AddressOfData);
					address = GetProcAddress(hInstance, (LPCSTR)importByName->Name);
				}

				if (address == NULL)
				{
					VirtualFree(imageBuffer, 0, MEM_RELEASE);
					return NULL;
				}
				ThunkData->u1.Function = (DWORD_PTR)address;
			}
		}
	}

	dos = (PIMAGE_DOS_HEADER)imageBuffer;
	nt = (PIMAGE_NT_HEADERS)((LONG_PTR)imageBuffer + dos->e_lfanew);
	nt->OptionalHeader.ImageBase = (DWORD_PTR)imageBuffer;

	return imageBuffer;
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
		if ((MBI.State & MEM_COMMIT) && (MBI.Protect == PAGE_EXECUTE_READWRITE))
		{
			if (memcmp((char*)Address+8, FileName, wcslen(FileName) * sizeof(wchar_t)) == 0)
			{
				//MessageBoxA(nullptr, "重复注入", "debug", 0);
				return Address;
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
