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

//rc4 decryption
int rc4(BYTE buf[], size_t len)
{
    //initialize S to the identity permutation
    Rc4ctx ctx;
    for (ctx.i = 0; ctx.i < 256; ctx.i++)
    {
        ctx.S[ctx.i] = ctx.i;
    }

    char key[5] = "Wiki";
    unsigned char temp;
    ctx.j = 0;
    for (ctx.i = 0; ctx.i < 256; ctx.i++)
    {
        ctx.j = (ctx.j + ctx.S[ctx.i] + key[ctx.i % strlen(key)]) % 256;
        temp = ctx.S[ctx.i];
        ctx.S[ctx.i] = ctx.S[ctx.j];
        ctx.S[ctx.j] = temp;
    }

    //pesudo random generation algorithm
    ctx.i = 0;
    ctx.j = 0;
    unsigned int cnt = 0;

    while (cnt <= len - 1)
    {
        ctx.i = (ctx.i + 1) % 256;
        ctx.j = (ctx.j + ctx.S[ctx.i]) % 256;
        temp = ctx.S[ctx.i];
        ctx.S[ctx.i] = ctx.S[ctx.j];
        ctx.S[ctx.j] = temp;

        unsigned int t = (ctx.S[ctx.i] + ctx.S[ctx.j]) % 256;
        unsigned int k = ctx.S[t];

        buf[cnt] = buf[cnt] ^ k;

        cnt++;
    }

    return 0;
}