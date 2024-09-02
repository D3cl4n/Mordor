.data
	wSystemCall DWORD 000h

.code 
	FuncY PROC
		nop
		mov wSystemCall, 000h
		nop
		mov wSystemCall, ecx
		nop
		ret
	FuncY ENDP

	FuncX PROC
		nop
		mov r10, rcx
		nop
		mov eax, wSystemCall
		nop
		syscall
		nop
		ret
	FuncX ENDP
end