#include "crt.h"


#include <stddef.h>

int WCSNCMPA(const wchar_t* lhs, const wchar_t* rhs, size_t count)
{
    if (count == 0)
    {
        return 0;
    }

    for (size_t i = 0; i < count; i++)
    {
        if (lhs[i] != rhs[i])
        {
            if (lhs[i] > rhs[i])
            {
                return 1;
            }
            else
            {
                return -1;
            }
        }

        if (lhs[i] == L'\0' || rhs[i] == L'\0')
        {
            break;
        }
    }

    return 0;
}



void EXITA(int status)
{
	ExitProcess(status);
}
