#include "framework.h"
#include "ConstEncrypt.h"

#define DeleteAntiQiapiaoObject
#define IDT_MYTIMER 0x88888888

HWND GameWindow = NULL;
HMODULE GameModule_TopKart = 0;
HMODULE GameModule_Network = 0;
UINT GameMemory_Base = 0;
UINT GameMemory_Base_Person = 0;
UINT GameMemory_Base_Person_Players = 0;
UINT GameMemory_Base_Person_Self = 0;
UINT GameMemory_Person_Kart = 0;
UINT GameMemory_Kart_Phys = 0;
UINT GameMemory_Kart_Phys_Param = 0;
UINT GameMemory_Kart_Phys_Param_AntiQiapiao = 0;
#ifndef DeleteAntiQiapiaoObject
UINT GameMemory_Kart_Phys_Param_AntiQiapiao_Banned = 0;
#endif

#define Get8(p) (*(const UINT8 *)(const void *)(p))
#define Get16(p) (*(const UINT16 *)(const void *)(p))
#define Get32(p) (*(const UINT32 *)(const void *)(p))
#define Get64(p) (*(const UINT64 *)(const void *)(p))

#define Set8(p, v) { *(UINT8 *)(p) = (v); }
#define Set16(p, v) { *(UINT16 *)(p) = (v); }
#define Set32(p, v) { *(UINT32 *)(p) = (v); }
#define Set64(p, v) { *(UINT64 *)(p) = (v); }



//#pragma optimize("", off)
void QQSpeed_Encrypt(int* key, char* data, int len) {
	int i;
	char v3, v6;
	*data ^= *(char*)key;
	v6 = *data;
	for (i = 1; i < len; ++i) {
		data[i] ^= ((char*)key)[i % 4];
		v3 = data[i];
		data[i] = v6;
		v6 = v3;
	}
	*data = v6;
}

void QQSpeed_Decrypt(int* key, char* data, int len)
{
	int i;
	char v3, v6;
	*data ^= *(char*)((int)key + (len - 1) % 4);
	v6 = *data;
	for (i = len - 1; i; --i)
	{
		data[i] ^= *(char*)((int)key + (i - 1) % 4);
		v3 = data[i];
		data[i] = v6;
		v6 = v3;
	}
	*data = v6;
}
//#pragma optimize("", on)


int Call_GetObject(int addr, int _ecx)
{
	int r = NULL;
	__asm {
		mov ecx, _ecx
		call addr
		mov[r], eax
	}
	return r;
}


void CALLBACK Timer_EnableQiapiao(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTimer)
{
	BOOL IsBanned = FALSE;
	UINT p = Get32(GameMemory_Base);
	UINT temp;
	if (p) {
		p = Get32(p + GameMemory_Base_Person);
		p = Get32(p + GameMemory_Base_Person_Self);
		if (p) {
			//p = Get32(p + GameMemory_Person_Kart);
			p = Call_GetObject(GameMemory_Person_Kart, p);
			//p = Get32(p + GameMemory_Kart_Phys);
			p = Call_GetObject(GameMemory_Kart_Phys, p);
			if (p) {
				//p = Get32(p + GameMemory_Kart_Phys_Param);
				p = Call_GetObject(GameMemory_Kart_Phys_Param, p);
				if (p) {
#ifdef DeleteAntiQiapiaoObject
					temp = Get32(p + GameMemory_Kart_Phys_Param_AntiQiapiao);
					if (temp)
					{
						Set32(p + GameMemory_Kart_Phys_Param_AntiQiapiao, NULL);
						delete (PVOID)temp;
						//MessageBoxA(GameWindow, "已删除反卡漂对象！", "debug", MB_OK);
					}
#else
					p = Get32(p + GameMemory_Kart_Phys_Param_AntiQiapiao);
					if (p) {
						QQSpeed_Encrypt((int*)(p + GameMemory_Kart_Phys_Param_AntiQiapiao_Banned), (char*)&IsBanned, 4);
						*(BOOL*)(*(int*)(p + GameMemory_Kart_Phys_Param_AntiQiapiao_Banned + 4)) = IsBanned;
					}
#endif
				}
			}
		}
	}
}

void CALLBACK Timer_Init(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTimer)
{
	SetTimer(GameWindow, IDT_MYTIMER, 1300, Timer_EnableQiapiao);
}


DWORD AOBScan(const char* Data, int DataLen, const char* Pattern, int PatternLen, const char* Mask) {
	int i, k;
	DataLen = (DataLen - PatternLen) + 1;
	for (i = 0; i < DataLen; i++) {
		for (k = 0; k < PatternLen; k++) {
			if (!(Mask[k] != 0 || Pattern[k] == (Data[k]))) {
				goto label;
			}
		}
		return (DWORD)Data;
	label:
		Data++;
	}
	return 0;
}

DWORD AOBScanModule(HMODULE hModule, DWORD Protect, int PatternLen, const char* Pattern, const char* Mask) {
	PIMAGE_NT_HEADERS PE = (PIMAGE_NT_HEADERS)((LONG)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	WORD SectionsNum = PE->FileHeader.NumberOfSections;
	WORD OptionalHeaderSize = PE->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER)((LPBYTE)PE + 4 + sizeof(IMAGE_FILE_HEADER) + OptionalHeaderSize);
	DWORD Result = 0;
	int Length = 0;
	int i;
	for (i = 0; SectionsNum > i; i++) {
		if ((Section->Characteristics & Protect) != 0) {
			Result = (DWORD)hModule + Section->VirtualAddress;
			Length = Section->Misc.VirtualSize;
			Result = AOBScan((char*)Result, Length, Pattern, PatternLen, Mask);
			if (Result) {
				break;
			}
		}
		Section++;
	}
	return Result;
}


DWORD WINAPI InitPlugin(LPVOID lpThreadParameter)
{
	HWND hWnd = 0;
	DWORD PID = 0;

	//获取游戏主窗口
	do {
		while ((hWnd = FindWindowExW(0, hWnd, XorString(L"GAMEAPP"), NULL)) == NULL) {
			Sleep(1600);
		}
		GetWindowThreadProcessId(hWnd, &PID);
	} while (PID != GetCurrentProcessId());
	GameWindow = hWnd;

	//等待显示
	while (!IsWindowVisible(GameWindow)) {
		Sleep(1000);
	}

	//特征码搜索
	DWORD Result, Address;
	wchar_t ResultString[1024];
	do
	{
		Sleep(1000);
		GameModule_TopKart = GetModuleHandleW(XorString(L"Top-Kart.dll"));
	} while (GameModule_TopKart == NULL);

#define DoEvents {SendMessageA(GameWindow, WM_NULL, 0, 0);}
#define FollowJump(a) { (Get32(a) + a + sizeof(INT32)) }

	DoEvents
	//2021-09
	//83 7D ?? 05 7D 15 8B
	Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 7,
		"\x83\x7D\x00\x05\x7D\x15\x8B",
		"\x00\x00\xFF\x00\x00\x00\x00");
	if (Result == 0) {
		//2021-09
		//8B 0D ???????? 83 EC 10 85 C9 75 09 83 C4 10 FF 25
		Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 18,
			"\x8B\x0D\x00\x00\x00\x00\x83\xEC\x10\x85\xC9\x75\x09\x83\xC4\x10\xFF\x25",
			"\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
		if (Result == 0) {
			Result = 1;
			goto label;
		}
		else {
			GameMemory_Base = Get32(Result + 2);
		}
	}
	else {
		GameMemory_Base = Get32(Result + 8);
	}

	DoEvents
	//2021-10-29
	//FF D0 8B 4D ?? 8B 91 ????0000 8B 45 ?? 8B 12 8B 88 ????0000 8B 82
	Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 24,
		"\xFF\xD0\x8B\x4D\x00\x8B\x91\x00\x00\x00\x00\x8B\x45\x00\x8B\x12\x8B\x88\x00\x00\x00\x00\x8B\x82",
		"\x00\x00\x00\x00\xFF\x00\x00\xFF\xFF\x00\x00\x00\x00\xFF\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x00");
	if (Result == 0) {
		//2021-09
		//FF D0 8B 4D ?? C7 81 ????0000 00000000 E8 ???????? E8
		Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 21,
			"\xFF\xD0\x8B\x4D\x00\xC7\x81\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8",
			"\x00\x00\x00\x00\xFF\x00\x00\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00");
		if (Result == 0) {
			Result = 2;
			goto label;
		}
		else {
			GameMemory_Base_Person = Get32(Result + 7);
		}
	}
	else {
		GameMemory_Base_Person = Get32(Result + 7);
	}

	DoEvents
	//2021-10-29
	//C7 45 FC 00 00 00 00 51 F3 0F 10 45 08 F3 0F 11 04 24 8B 4D ?? 8B 91
	Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 23,
		"\xC7\x45\xFC\x00\x00\x00\x00\x51\xF3\x0F\x10\x45\x08\xF3\x0F\x11\x04\x24\x8B\x4D\x00\x8B\x91",
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00\x00");
	if (Result == 0) {
		//2021-05
		//74 10 8B 95 ????FFFF C7 82 ????0000 00 00 00 00
		Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 18,
			"\x74\x10\x8B\x95\x00\x00\xFF\xFF\xC7\x82\x00\x00\x00\x00\x00\x00\x00\x00",
			"\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x00\x00\x00");
		if (Result == 0) {
			Result = 3;
			goto label;
		}
		else {
			GameMemory_Base_Person_Self = Get32(Result + 10);
		}
	}
	else {
		GameMemory_Base_Person_Self = Get32(Result + 23);
	}

	DoEvents
	//2021-05
	//00 00 FF D0 8B C8 E8 ???????? 8B C8 E8 ???????? 8B C8 E8 ???????? 8B C8 E8 ???????? 85 C0
	Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 34,
		"\x00\x00\xFF\xD0\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x85\xC0",
		"\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00");
	if (Result == 0) {
		//2021-05
		//E8???????? 8B C8 E8???????? 8B C8 E8???????? 8B C8 E8???????? 89 45 FC 8B 4D FC
		Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 32,
			"\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x89\x45\xFC\x8B\x4D\xFC",
			"\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00");
		if (Result == 0) {
			Result = 4;
			goto label;
		}
		else {
			Address = Result + 7;
			Address = FollowJump(Address + 1);
			//Address = Get32(Address + 12);
			GameMemory_Person_Kart = Address;

			Address = Result + 14;
			Address = FollowJump(Address + 1);
			//Address = Get8(Address + 12);
			GameMemory_Kart_Phys = Address;

			Address = Result + 21;
			Address = FollowJump(Address + 1);
			//Address = Get32(Address + 12);
			GameMemory_Kart_Phys_Param = Address;
		}
	}
	else {
		Address = Result + 6;
		Address = FollowJump(Address + 1);
		//Address = Get32(Address + 12);
		GameMemory_Person_Kart = Address;

		Address = Result + 13;
		Address = FollowJump(Address + 1);
		//Address = Get8(Address + 12);
		GameMemory_Kart_Phys = Address;

		Address = Result + 20;
		Address = FollowJump(Address + 1);
		//Address = Get32(Address + 12);
		GameMemory_Kart_Phys_Param = Address;
	}

	DoEvents
	//2022-03
	//8B 45 08 D9 58 ?? 8B 4D ?? E8 ???????? 85 C0 74
	Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 17,
		"\x8B\x45\x08\xD9\x58\x00\x8B\x4D\x00\xE8\x00\x00\x00\x00\x85\xC0\x74",
		"\x00\x00\x00\x00\x00\xFF\x00\x00\xFF\x00\xFF\xFF\xFF\xFF\x00\x00\x00");
	if (Result == 0) {
		Result = 5;
		goto label;
	}
	else {
		Address = Result + 9;
		Address = FollowJump(Address + 1);
		Address = Get8(Address + 12);
		GameMemory_Kart_Phys_Param_AntiQiapiao = Address;
	}
#ifndef DeleteAntiQiapiaoObject
	DoEvents
	//2022-03
	//C6 45 ?? 00 C7 45 ?? 01000000 8D 45 ?? 50 8B 4D ?? 83 C1 ?? E8
	Result = AOBScanModule(GameModule_TopKart, IMAGE_SCN_CNT_CODE, 22,
		"\xC6\x45\x00\x00\xC7\x45\x00\x01\x00\x00\x00\x8D\x45\x00\x50\x8B\x4D\x00\x83\xC1\x00\xE8",
		"\x00\x00\xFF\x00\x00\x00\xFF\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00\xFF\x00\x00\xFF\x00");
	if (Result == 0) {
		Result = 6;
		goto label;
	}
	else {
		Address = Result + 19;
		Address = Get8(Address + 2);
		GameMemory_Kart_Phys_Param_AntiQiapiao_Banned = Address;
	}
#endif

	SetTimer(GameWindow, IDT_MYTIMER, 1, Timer_Init);//有些操作必须在主线程执行
	return 0;
label:
	wsprintfW(ResultString, XorString(L"未适配当前游戏版本！错误代码：%d"), Result);
	MessageBoxW(hWnd, ResultString, XorString(L"卡漂插件"), MB_OK);
	return Result;
}
