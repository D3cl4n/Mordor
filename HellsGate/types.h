#ifndef TYPES_H
#define TYPES_H


#include <Windows.h>
#include <stdio.h>


//structure for containing the three arrays from the export directory
struct ExportDirectoryData {
	PDWORD pFunctionNameArr;
	PDWORD pFunctionOrdinalArr;
	PDWORD pFunctionAddressArr;
};

//VxTableEntry represents a syscall's information
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;             // The address of a syscall function
	DWORD64 dwHash;               // The djb2 hash value of the syscall name
	WORD    wSystemCall;          // The SSN of the syscall
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

//table of VxTableEntries
typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

//rc4 context
typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char S[256];
} Rc4ctx;

//all the SSNs needed for local process injection
typedef struct
{
	unsigned int NtAllocateVirtualMemorySSN;
	unsigned int NtCreateThreadExSSN;
	unsigned int NtWriteVirtualMemorySSN;
	unsigned int NtProtectVirtualMemorySSN;
	unsigned int NtWaitForSingleObjectSSN;
} UnhookedSSNs;

#endif // !TYPES_H