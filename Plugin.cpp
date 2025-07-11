#include "framework.h"

//#define DeleteAntiQiapiaoObject

#define Get8(p) (*(const UINT8 *)(const void *)(p))
#define Get16(p) (*(const UINT16 *)(const void *)(p))
#define Get32(p) (*(const UINT32 *)(const void *)(p))
#define Get64(p) (*(const UINT64 *)(const void *)(p))

#define Set8(p, v) { *(UINT8 *)(p) = (v); }
#define Set16(p, v) { *(UINT16 *)(p) = (v); }
#define Set32(p, v) { *(UINT32 *)(p) = (v); }
#define Set64(p, v) { *(UINT64 *)(p) = (v); }

//相对寻址
_inline UINT_PTR RelativeAddressing8(UINT_PTR a)
{
	return (INT_PTR)*(INT8*)a + a + sizeof(INT8);
}
_inline UINT_PTR RelativeAddressing32(UINT_PTR a)
{
	return (INT_PTR)*(INT32*)a + a + sizeof(INT32);
}


UINT_PTR g_TimerID;

namespace QQSpeed
{
	HWND MainWindow = NULL;
	HMODULE Module_TopKart = 0;
	UINT_PTR Memory_Base = 0; //CGameMain
	UINT_PTR Memory_Base_PlayerMgr = 0; //CNxPlayerMgr
	UINT_PTR Memory_Base_PlayerMgr_Self = 0; //CNxPlayer
	UINT_PTR Memory_Player_Kart = 0;
	UINT_PTR Memory_Kart_Phys = 0;
	UINT_PTR Memory_Kart_Phys_Param = 0; //CCoreKart CDriftCenter
	UINT_PTR Memory_Kart_Phys_Param_AntiQiapiao = 0;
	UINT_PTR Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0;

	void memoryEncrypt(int* key, char* data, int len)
	{
		char v3, v6;
		v6 = *data ^ *(char*)key;
		for (int i = 1; i < len; ++i)
		{
			v3 = data[i] ^ ((char*)key)[i % 4];
			data[i] = v6;
			v6 = v3;
		}
		*data = v6;
	}

	void memoryDecrypt(int* key, char* data, int len)
	{
		char v3, v6;
		v6 = *data ^ ((char*)key)[(len - 1) % 4];
		for (int i = len - 1; i; --i)
		{
			v3 = data[i] ^ ((char*)key)[(i - 1) % 4];
			data[i] = v6;
			v6 = v3;
		}
		*data = v6;
	}

	UINT_PTR getObject(UINT_PTR CallAddr, UINT_PTR This)
	{
		return ((UINT_PTR(__thiscall*)(UINT_PTR)) CallAddr)(This);
	}

#pragma pack(push, 8)
	class EncryptBoolPtr
	{
	public:
		int key;
		BOOL* data; // 2022年03月 从 BOOL 变成 BOOL*

		void set(BOOL value)
		{
			//改值应该顺便更新key, 这里不做更新
			QQSpeed::memoryEncrypt(&key, (char*)&value, sizeof(BOOL));
			*data = value;
		}

		BOOL get()
		{
			BOOL value = *data;
			QQSpeed::memoryDecrypt(&key, (char*)&value, sizeof(BOOL));
			return value;
		}
	};
#pragma pack(pop)
	static_assert(sizeof(BOOL) == 4, "错误的大小");
#if defined(_M_IX86)
	static_assert(sizeof(EncryptBoolPtr) == 8, "错误的结构大小");
#elif defined(_M_AMD64)
	static_assert(sizeof(EncryptBoolPtr) == 16, "错误的结构大小");
#endif
}

void CALLBACK Timer_AntiAntiQiapiao(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
{
#if defined(_M_IX86)
	UINT_PTR p = QQSpeed::getObject(QQSpeed::Memory_Base, NULL);
	if (p) {
		p = QQSpeed::getObject(Get32(Get32(p) + QQSpeed::Memory_Base_PlayerMgr), p);
		p = QQSpeed::getObject(Get32(Get32(p) + QQSpeed::Memory_Base_PlayerMgr_Self), p);
		if (p) {
			p = Get32(p + QQSpeed::Memory_Player_Kart);
			p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys, p);
			if (p) {
				p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys_Param, p);
				if (p) {
#ifdef DeleteAntiQiapiaoObject
					UINT temp = Get32(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (temp)
					{
						Set32(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao, NULL);
						delete (PVOID)temp;
					}
#else
					p = Get32(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (p)
					{
						QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable);
						EncryptData->set(FALSE); //禁用反卡漂
					}
#endif
				}
			}
		}
	}
#elif defined(_M_AMD64)
	UINT_PTR p = QQSpeed::getObject(QQSpeed::Memory_Base, NULL);
	if (p) {
		p = QQSpeed::getObject(Get64(Get64(p) + QQSpeed::Memory_Base_PlayerMgr), p);
		p = QQSpeed::getObject(Get64(Get64(p) + QQSpeed::Memory_Base_PlayerMgr_Self), p);
		if (p) {
			p = Get64(p + QQSpeed::Memory_Player_Kart);
			p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys, p);
			if (p) {
				p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys_Param, p);
				if (p) {
#ifdef DeleteAntiQiapiaoObject
					UINT temp = Get64(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (temp)
					{
						Set64(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao, NULL);
						delete (PVOID)temp;
					}
#else
					p = Get64(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (p)
					{
						QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable);
						EncryptData->set(FALSE); //禁用反卡漂
					}
#endif
				}
			}
		}
	}
#endif
}

void CALLBACK Timer_Init(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
{
	api.SetTimer(hwnd, iTimerID, 1300, Timer_AntiAntiQiapiao);
}

//Array Of Byte Scan
char* AOBScan(const char* bytes, size_t bytes_len, const char* pattern, size_t pattern_len, const char* mask)
{
	for (const char* tail = bytes + (bytes_len - pattern_len); bytes <= tail; bytes++)
	{
		for (size_t i = 0; i < pattern_len; i++)
			if (((bytes[i] ^ pattern[i]) & mask[i]) != 0) goto label;
		return (char*)bytes;
	label:;
	}
	return NULL;
}

UINT_PTR AOBScanModule(HMODULE hModule, DWORD section_characteristics, size_t pattern_len, const char* pattern, const char* mask)
{
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((UINT_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	WORD num = pe->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((UINT_PTR)pe + sizeof(pe->Signature) + sizeof(IMAGE_FILE_HEADER) + pe->FileHeader.SizeOfOptionalHeader);
	for (WORD i = 0; num > i; i++, section++)
		if ((section->Characteristics & section_characteristics) != 0)
			if (UINT_PTR result = (UINT_PTR)AOBScan((char*)hModule + section->VirtualAddress, section->Misc.VirtualSize, pattern, pattern_len, mask))
				return result;
	return NULL;
}

DWORD GetModuleCompileTime(HMODULE hModule)
{
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((UINT_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	return pe->FileHeader.TimeDateStamp;
}

DWORD WINAPI InitPlugin(LPVOID lpThreadParameter)
{
	HWND hWnd = 0;
	DWORD PID = 0;

	//获取主窗口句柄
	do {
		while ((hWnd = api.FindWindowExW(0, hWnd, XorString(L"GAMEAPP"), NULL)) == NULL) {
			api.Sleep(500);
		}
		api.GetWindowThreadProcessId(hWnd, &PID);
	} while (PID != api.GetCurrentProcessId());
	QQSpeed::MainWindow = hWnd;

	//获取模块基址
	UINT_PTR Result, Address;
	DWORD Reason;
	do
	{
		api.Sleep(1000);
		QQSpeed::Module_TopKart = api.GetModuleHandleW(XorString(L"Top-Kart.dll"));
	} while (QQSpeed::Module_TopKart == NULL);

	//特征码定位
	DWORD time = GetModuleCompileTime(QQSpeed::Module_TopKart);
	do
	{
#if defined(_M_IX86)
		if (time < 1333238400) // 2012-04-01
		{
			// 更旧的版本未封禁卡漂
			Reason = 4;
			break;
		}
		else if (time > 1682553600) // 2023-04-27
		{
			//适用于 Beta83 熔炉盛典 Date:2023-04-28
			//E8 ???????? 8B C8 8B 10 FF 52 ?? 8B C8 8B 10 FF 92 ????0000 8B 88 ????0000 E8 ???????? 8B C8 E8 ???????? 8B C8 E8
			Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 43,
				"\xE8\x00\x00\x00\x00\x8B\xC8\x8B\x10\xFF\x52\x00\x8B\xC8\x8B\x10\xFF\x92\x00\x00\x00\x00\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8",
				"\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF");
			if (Result == 0) {
				Reason = 1;
				break;
			}
			else {
				Address = Result;
				Address = RelativeAddressing32(Address + 1);
				QQSpeed::Memory_Base = Address; //函数

				Address = Result + 5 + 2 + 2;
				QQSpeed::Memory_Base_PlayerMgr = Get8(Address + 2); //虚函数

				Address = Result + 5 + 2 + 2 + 3 + 2 + 2;
				QQSpeed::Memory_Base_PlayerMgr_Self = Get32(Address + 2); //虚函数

				Address = Result + 5 + 2 + 2 + 3 + 2 + 2 + 6;
				QQSpeed::Memory_Player_Kart = Get32(Address + 2); //偏移

				Address = Result + 5 + 2 + 2 + 3 + 2 + 2 + 6 + 6;
				Address = RelativeAddressing32(Address + 1);
				QQSpeed::Memory_Kart_Phys = Address; //函数

				Address = Result + 5 + 2 + 2 + 3 + 2 + 2 + 6 + 6 + 5 + 2;
				Address = RelativeAddressing32(Address + 1);
				QQSpeed::Memory_Kart_Phys_Param = Address; //函数
			}
			QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao = 0x4C;
			QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0x48;
		}
		else if (time > 1450310400) // 2015-12-17
		{
			//这通常是私服才能登录旧版本，且似乎没有CRC检测，所以如此这般
			//适用于 Beta28 辉煌之路 ~ Beta82 龙晶大闯关
/*
Top-Kart.dll+2D8CB - C6 45 FB 00           - mov byte ptr [ebp-05],00
Top-Kart.dll+2D8CF - C7 45 F0 01000000     - mov [ebp-10],00000001 { 是否封禁卡漂,改0解 }
Top-Kart.dll+2D8D6 - 8D 45 F0              - lea eax,[ebp-10]
Top-Kart.dll+2D8D9 - 50                    - push eax
Top-Kart.dll+2D8DA - 8B 4D C0              - mov ecx,[ebp-40]
Top-Kart.dll+2D8DD - 83 C1 4C              - add ecx,4C
Top-Kart.dll+2D8E0 - E8 8E494002           - call Top-Kart.dll+2432273
Top-Kart.dll+2D8E5 - C6 45 FB 01           - mov byte ptr [ebp-05],01
*/
			//C6 45 ?? 00 C7 45 ?? 01000000 8D 45 ?? 50 8B 4D ?? 83 C1 ?? E8
			Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 22,
				"\xC6\x45\x00\x00\xC7\x45\x00\x01\x00\x00\x00\x8D\x45\x00\x50\x8B\x4D\x00\x83\xC1\x00\xE8",
				"\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\x00\xFF");
			if (Result == 0) {
				Reason = 3;
				break;
			}
			else {
				int* p = (int*)(Result + 7);
				DWORD oldProtect;
				api.VirtualProtect(p, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect);
				*p = 0;
				api.VirtualProtect(p, sizeof(int), oldProtect, &oldProtect);
				return 0;
			}
		}
		else
		{
			// 不支持
			Reason = 2;
			break;
		}
#elif defined(_M_AMD64)
		//适用于 Beta88 幻域大闯关 Date:2024-03-05
		//不支持 Beta96 Ver19994 Date:2025-06-24, 但支持 Beta96 Ver20012 Date:2025-07-02
		//E8 ???????? 48 8B C8 48 8B 10 FF 52 ?? 48 8B C8 48 8B 10 FF 92 ????0000 48 8B 88 ????0000 E8 ???????? 48 8B C8 E8 ???????? 48 8B C8 E8
		Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 50,
			"\xE8\x00\x00\x00\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x52\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x92\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8",
			"\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF");
		if (Result == 0) {
			Reason = 1;
			break;
		}
		else {
			Address = Result;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Base = Address; //函数

			Address = Result + 5 + 3 + 3;
			QQSpeed::Memory_Base_PlayerMgr = Get8(Address + 2); //虚函数

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3;
			QQSpeed::Memory_Base_PlayerMgr_Self = Get32(Address + 2); //虚函数

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3 + 6;
			QQSpeed::Memory_Player_Kart = Get32(Address + 3); //偏移

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3 + 6 + 7;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Kart_Phys = Address; //函数

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3 + 6 + 7 + 5 + 3;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Kart_Phys_Param = Address; //函数
		}

		QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao = 0x90;
		QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0x90;
#else
#error 仅支持x86和x64
#endif
		g_TimerID = (UINT_PTR)&Timer_Init;
		api.SetTimer(QQSpeed::MainWindow, g_TimerID, 1, Timer_Init);//有些操作必须在主线程执行
		return 0;
	} while (false);
	wchar_t string[1024];
	api.wsprintfW(string, XorString(L"未适配当前游戏版本！错误代码：%d"), Reason);
	api.MessageBoxTimeoutW(hWnd, string, XorString(L"卡漂插件"), MB_OK, 0, 5000);
	return Reason;
}
