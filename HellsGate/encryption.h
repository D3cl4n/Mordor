#ifndef ENCRYPTION_H
#define ENCRYPTIO_H

#include <stdio.h>
#include <Windows.h>

/*
* Desc: XOR decrypts the shellcode
* Param: BYTE buf[] -> pointer to first byte of an array of BYTE
* Returns: void
*/
void XorShellcode(BYTE buf[], size_t len);

/*
* Desc: the djb2 hashing algorithm
* Param: PBYTE str -> the plaintext to hash
* Returns: DWORD64 the value of the ciphertext / hash value
*/
DWORD64 djb2(PBYTE str);


int rc4(BYTE buf[], size_t len);


#endif