.data
	wSystemCall DWORD 000h

.code 
	FuncY PROC
		nop
		mov wSystemCall, 000h
		nop
		mov wSystemCall, ecx
		xor ecx, ecx
		nop
		ret
	FuncY ENDP

	FuncX PROC
		nop
		xor r10, r10
		mov r10, rcx
		nop
		xor eax, eax
		mov eax, wSystemCall
		nop
		syscall
		nop
		ret
	FuncX ENDP
end