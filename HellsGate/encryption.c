#include "encryption.h"
#include "utils.h"
#include "crt.h"

//implemetation for XorShellcode
void XorShellcode(BYTE buf[], size_t len)
{
	char key[] = "A";

	for (size_t i = 0; i < (len - 1); i++)
	{
		buf[i] = buf[i] ^ key[i % (sizeof(key) - 1)];
	}

}

//implementation of djb2 hashing algorithm
DWORD64 djb2(PBYTE str)
{
	DWORD64 dwHash = 0x1337539; //seed
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}