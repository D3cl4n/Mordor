#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>
#include <intrin.h>

#include "types.h"

/*
* Desc: Gets the address of the Process Environment Block (PEB)
* Returns: PPEB -> pointer to PEB structure
*/
PPEB GetPEBAddress();

/*
* Desc: Gets the address of PEB_LDR_DATA struct within PEB
* Param: PPEB peb-> pointer to PEB structure for the process's PEB
* Returns: PPEB_LDR_DATA -> pointer to PEB_LDR_DATA struct
*/
PPEB_LDR_DATA GetLdrAddress(PPEB peb);

/*
* Desc: Gets the address of the first entry in InMemoryOrderModuleList
*/
PLIST_ENTRY GetModuleList(PPEB_LDR_DATA ldr_ptr);

/*
* Desc: Gets the base address of a module via PEB walk
* Param: const PWSTR target_dll -> the name of the module to resolve
* Param: PLIST_ENTRY head_node -> the first LIST_ENTRY in InMemoryOrderModuleList
*/
DWORD_PTR GetModuleBaseAddr(const PWSTR target_dll, PLIST_ENTRY head_node);

/*
* Desc: Gets the NT HEADER from the module base
* Param: PBYTE pBase -> the base address of the module
* Returns: PIMAGE_NT_HEADERS -> the NT Header struct
*/

PIMAGE_NT_HEADERS GetNTHeader(PBYTE pBase, PIMAGE_DOS_HEADER pDosHeader);

/*
* Desc: Gets the address of the image export directory
* Param: PBYTE pBase -> base address of the module we are parsing
* Param: PIMAGE_NT_HEADERS pNtHeader -> NT header struct
* Returns: PIMAGE_EXPORT_DIRECTORY -> pointer to struct representing export directory
*/
PIMAGE_EXPORT_DIRECTORY GetImgExportDir(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeader);

/*
* Desc: finds the addresses of the syscalls based on djb2 hash matches, then stores the SSNs
* Param: PVOID pBase -> module base
* Param: PIMAGE_EXPORT_DIRECTORY pExportDir -> export directory of module
* Param: PVX_TABLE_ENTRY pVxTableEntry -> address of entry to populate
* Param: struct ExportDirectoryData* pData -> struct containing pointers to arrays on function info
* Returns: True on success, False otherwise
*/
BOOL GetVxTableEntry(PVOID pBase, PIMAGE_EXPORT_DIRECTORY pExportDir, PVX_TABLE_ENTRY pVxTableEntry);

