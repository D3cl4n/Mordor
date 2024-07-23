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

}