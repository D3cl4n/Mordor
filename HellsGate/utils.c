#include <Windows.h>
#include <winternl.h>

#include "utils.h"


//implementation of GetPEBAddress
PPEB GetPEBAddress()
{
	return (PPEB)__readfsdword(0x30);
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
DWORD_PTR GetModuleBaseAddr(const PWSTR target_dll, PLIST_ENTRY head_node)
{
	DWORD_PTR module_addr = 0;
	PLIST_ENTRY temp = head_node->Flink;
	while (temp != head_node)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(temp, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (wcsncmp(target_dll, entry->FullDllName.Buffer, wcslen(target_dll)) == 0)
		{
			module_addr = (DWORD_PTR)entry->DllBase;
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
