#include "encryption.h"

//implemetation for XorShellcode
void XorShellcode(BYTE buf[])
{
	char key[] = "A"; //TODO: change this
	printf("[+] XOR shellcode with key %s\n", key);
	size_t length = sizeof(buf);
	printf("[+] Shellcode length: %zu\n", length);

	for (size_t i = 0; i < (length - 1); i++)
	{
		buf[i] = buf[i] ^ key[i % (sizeof(key) - 1)];
	}
	printf("[+] Finished decrypting shellcode\n");
}