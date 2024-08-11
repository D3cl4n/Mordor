#include "encryption.h"

//implemetation for XorShellcode
void XorShellcode(BYTE buf[], size_t len)
{
	char key[] = "A"; //TODO: change this
	printf("[+] XOR shellcode with key %s\n", key);

	for (size_t i = 0; i < (len - 1); i++)
	{
		buf[i] = buf[i] ^ key[i % (sizeof(key) - 1)];
	}
	printf("\t[*] Finished decrypting shellcode\n");
}

//implementation of djb2 hashing algorithm
DWORD64 djb2(PBYTE str)
{
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}