#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>
#include <intrin.h>

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
