#include "framework.h"
#include "PELoader.h"


static void* LoadFileData(const wchar_t* path, size_t* size)
{
	// 打开文件
	HANDLE hFile = api.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	void* data = NULL;
	LARGE_INTEGER fileSize;
	DWORD bytesRead;
	size_t remainingSize;
	char* ptr;
	const DWORD chunkSize = 8 * 1024 * 1024; // 8MB
	DWORD currentChunkSize;
	// 获取文件大小
	if (!api.GetFileSizeEx(hFile, &fileSize)) {
		goto label;
	}
	remainingSize = (size_t)fileSize.QuadPart;
	*size = remainingSize;
	// 分配内存
	data = api.malloc(remainingSize);
	if (!data) {
		goto label;
	}
	// 分块读取文件，针对大于 4GB 的文件
	ptr = (char*)data;
	currentChunkSize = min(chunkSize, (DWORD)remainingSize);
	while (remainingSize > 0) {
		if (!api.ReadFile(hFile, ptr, currentChunkSize, &bytesRead, NULL)) {
			api.free(data);
			data = NULL;
			goto label;
		}
		ptr += bytesRead;
		remainingSize -= bytesRead;
	}
label:
	// 关闭文件
	api.CloseHandle(hFile);
	return data;
}


void ProcessBaseReloc(char* buffer, const PIMAGE_NT_HEADERS pNtHeaders, UINT_PTR oldBase, UINT_PTR newBase)
{
	PIMAGE_DATA_DIRECTORY pDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pDir->Size > 0)
	{
		UINT_PTR deltaBase = newBase - oldBase;
		IMAGE_BASE_RELOCATION* pBaseRelocation = (IMAGE_BASE_RELOCATION*)(buffer + pDir->VirtualAddress);
		UINT_PTR endPtr = (UINT_PTR)pBaseRelocation + pDir->Size;
		while (endPtr > (UINT_PTR)pBaseRelocation)
		{
			UINT_PTR address = (UINT_PTR)buffer + pBaseRelocation->VirtualAddress;
			WORD* blockPtr = (WORD*)((UINT_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
			UINT_PTR blockEndPtr = (UINT_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock;
			while (blockEndPtr > (UINT_PTR)blockPtr)
			{
				WORD Type = *blockPtr >> 0x0C;
				WORD Offset = *blockPtr & 0x0FFF;

				if (Type == IMAGE_REL_BASED_ABSOLUTE)
				{
					//无意义
				}
#ifndef _WIN64
				else if (Type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(UINT32*)(address + Offset) += deltaBase;
				}
#else
				else if (Type == IMAGE_REL_BASED_DIR64)
				{
					*(UINT64*)(address + Offset) += deltaBase;
				}
#endif
				blockPtr++;
			}
			pBaseRelocation = (IMAGE_BASE_RELOCATION*)blockEndPtr;
		}
	}
}

BOOL ProcessImportTable(char* pImageBuffer, const PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_DATA_DIRECTORY pDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pDir->Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(pImageBuffer + pDir->VirtualAddress);

		for (; ImportDescriptor->Characteristics; ImportDescriptor++)
		{
			char* name = pImageBuffer + ImportDescriptor->Name;
			HMODULE hModule = api.LoadLibraryA(name);
			if (hModule == NULL)
			{
				return FALSE;
			}
			IMAGE_THUNK_DATA* pThunkData = (IMAGE_THUNK_DATA*)(pImageBuffer + ImportDescriptor->FirstThunk);
			for (; pThunkData->u1.Ordinal; pThunkData++)
			{
				FARPROC address;
				if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					UINT_PTR ordinal = IMAGE_ORDINAL(pThunkData->u1.Ordinal);
					address = api.GetProcAddress(hModule, (LPCSTR)ordinal);
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* pName = (IMAGE_IMPORT_BY_NAME*)(pImageBuffer + pThunkData->u1.AddressOfData);
					address = api.GetProcAddress(hModule, (LPCSTR)pName->Name);
				}

				if (address == NULL)
				{
					return FALSE;
				}
				pThunkData->u1.Function = (UINT_PTR)address;
			}
		}
	}
	return TRUE;
}

PVOID LoadPEFileData(char* pFileData)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pFileData;
	if (IMAGE_DOS_SIGNATURE != dos->e_magic) return NULL;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((UINT_PTR)pFileData + dos->e_lfanew);
	if (IMAGE_NT_SIGNATURE != nt->Signature) return NULL;
#ifdef _WIN64
	if (IMAGE_FILE_MACHINE_AMD64 != nt->FileHeader.Machine) return NULL;
#else
	if (IMAGE_FILE_MACHINE_I386 != nt->FileHeader.Machine) return NULL;
#endif

	DWORD imageSize = nt->OptionalHeader.SizeOfImage;
	char* imageBuffer = (char*)api.VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (imageBuffer == NULL)
	{
		return NULL;
	}

	//Header
	my_memcpy(imageBuffer, pFileData, nt->OptionalHeader.SizeOfHeaders);

	//Section
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((UINT_PTR)nt + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
	WORD sectionNumber = nt->FileHeader.NumberOfSections;
	for (WORD i = 0; i < sectionNumber; i++)
	{
		my_memcpy(imageBuffer + sections[i].VirtualAddress, pFileData + sections[i].PointerToRawData, sections[i].SizeOfRawData);
	}

	//BaseReloc
	ProcessBaseReloc(imageBuffer, nt, (UINT_PTR)nt->OptionalHeader.ImageBase, (UINT_PTR)imageBuffer);

	//Import
	if(!ProcessImportTable((char*)imageBuffer, nt))
	{
		api.VirtualFree(imageBuffer, 0, MEM_RELEASE);
		return NULL;
	}

	dos = (PIMAGE_DOS_HEADER)imageBuffer;
	nt = (PIMAGE_NT_HEADERS)((UINT_PTR)imageBuffer + dos->e_lfanew);
	nt->OptionalHeader.ImageBase = (UINT_PTR)imageBuffer;

	return imageBuffer;
}

BOOL InvokeDllMain(PVOID hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	auto fnDllMain = (BOOL (WINAPI *)(HMODULE, DWORD, LPVOID)) ((DWORD_PTR)hModule + nt->OptionalHeader.AddressOfEntryPoint);
	return fnDllMain((HMODULE)hModule, ul_reason_for_call, lpReserved);
}

VOID ZeroPEHeader(PVOID hModule)
{
	api.memset(hModule, 0, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew + sizeof(IMAGE_NT_HEADERS));
}

PVOID FindLoadedDll(const wchar_t* fileName)
{
	PVOID address = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	while (api.VirtualQuery(address, &mbi, sizeof(mbi)) != 0)
	{
		address = mbi.BaseAddress;
		if ((mbi.State & MEM_COMMIT) && (mbi.Protect == PAGE_EXECUTE_READWRITE))
		{
			if (api.memcmp((char*)address + 8, fileName, api.wcslen(fileName) * sizeof(wchar_t)) == 0)
			{
				return address;
			}
		}
		address = (PVOID)((SIZE_T)address + mbi.RegionSize);
	}
	return NULL;
}

VOID MarkDllAsLoaded(PVOID imageBase, const wchar_t* fileName)
{
	my_memcpy((char*)imageBase + 8, fileName, api.wcslen(fileName) * sizeof(wchar_t));
}

PVOID LoadDll(const wchar_t* fileName, DWORD reason)
{
	PVOID fileData = NULL;
	size_t fileSize = 0;
	PVOID imageBase = FindLoadedDll(fileName);
	if (imageBase)
	{
		return imageBase;
	}
	if ((fileData = LoadFileData(fileName, &fileSize)) && (imageBase = LoadPEFileData((char*)fileData)))
	{
		api.memset(fileData, 0, fileSize);
		api.free(fileData);
		InvokeDllMain(imageBase, reason, (PVOID)fileName);
		InvokeDllMain(imageBase, DLL_PROCESS_ATTACH, NULL);
		ZeroPEHeader(imageBase);
		MarkDllAsLoaded(imageBase, fileName);
	}
	return imageBase;
}
