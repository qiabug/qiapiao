#include "framework.h"
//#include <winnt.h>


#if defined(_M_IX86)
#define GET_PEB() (uintptr_t)__readfsdword(0x30)
#elif defined(_M_AMD64)
#define GET_PEB() (uintptr_t)__readgsqword(0x60)
#endif


struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct MY_LIST_ENTRY
{
    struct MY_LIST_ENTRY *Flink;
    struct MY_LIST_ENTRY *Blink;
};

struct PEB_LDR_DATA
{
    ULONG             Length;
    UCHAR             Initialized;
    VOID*             SsHandle;
    struct MY_LIST_ENTRY InLoadOrderModuleList;
    struct MY_LIST_ENTRY InMemoryOrderModuleList;
    struct MY_LIST_ENTRY InInitializationOrderModuleList;
    VOID*             EntryInProgress;
    UCHAR             ShutdownInProgress;
    VOID*             ShutdownThreadId;
};

struct PEB
{
    UCHAR                InheritedAddressSpace;
    UCHAR                ReadImageFileExecOptions;
    UCHAR                BeingDebugged;
    UCHAR                BitField;
    VOID*                Mutant;
    VOID*                ImageBaseAddress;
    struct PEB_LDR_DATA* Ldr;
    // 省略...
};

struct LDR_DATA_TABLE_ENTRY
{
    struct MY_LIST_ENTRY     InLoadOrderLinks;
    struct MY_LIST_ENTRY     InMemoryOrderLinks;
    struct MY_LIST_ENTRY     InInitializationOrderLinks;
    VOID*                 DllBase;
    VOID*                 EntryPoint;
    ULONG                 SizeOfImage;
    struct UNICODE_STRING FullDllName;
    struct UNICODE_STRING BaseDllName;
    ULONG                 Flags;
    USHORT                LoadCount;
    USHORT                TlsIndex;
    // 省略...
};


//GetModuleHandle
void* GetModuleBase(const wchar_t* name)
{
	struct PEB* peb = (struct PEB*)GET_PEB();
    struct MY_LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
    struct LDR_DATA_TABLE_ENTRY* entry = (struct LDR_DATA_TABLE_ENTRY*)head->Flink;
    while((struct MY_LIST_ENTRY*)entry != head)
    {
        if (my_wcsnicmp(entry->BaseDllName.Buffer, name, entry->BaseDllName.Length) == 0)
        {
            return entry->DllBase;
        }
        entry = (struct LDR_DATA_TABLE_ENTRY*)entry->InLoadOrderLinks.Flink;
    }
    return NULL;
}

//GetProcAddress
void* GetProcedureAddress(void* base, const char* name)
{
    IMAGE_DOS_HEADER* dos = (PIMAGE_DOS_HEADER)base;
    IMAGE_NT_HEADERS* nt = (PIMAGE_NT_HEADERS)((UINT_PTR)base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->Size > 0)
    {
        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((UINT_PTR)base + dir->VirtualAddress);
        DWORD* names = (DWORD*)((UINT_PTR)base + exportDir->AddressOfNames);
        DWORD* functions = (DWORD*)((UINT_PTR)base + exportDir->AddressOfFunctions);
        WORD* ordinals = (WORD*)((UINT_PTR)base + exportDir->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++)
        {
            if (my_strcmp((char*)base + names[i], name) == 0)
            {
                return (void*)((UINT_PTR)base + functions[ordinals[i]]);
            }
        }
    }
    return NULL;
}
