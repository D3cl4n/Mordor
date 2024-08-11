# Mordor
![image](https://github.com/D3cl4n/Mordor/blob/master/mordor.jpg)

## About
Hell's Gate with XOR encryption, performs local shellcode injection via direct syscalls. Includes custom API for functionality related to GetProcAddress and GetModuleHandle. Credit goes to the original Hell's Gate researchers. Their paper can be found here https://github.com/am0nsec/HellsGate/blob/master/hells-gate.pdf 

## Description
Hell's Gate is a known method of performing direct system calls. Because EDR can hook NtAPI functions, and System Service Numbers (SSNs) can change whenever Microsoft wants to change them, dynamically resolving SSNs then performing direct syscalls is a good strategy. We need to find the base address of ntdll.dll in memory, then parse through it to find the addresses of the NtAPI functions needed for local shellcode injection. Once the addresses of these functions are found, we can extract that function's SSN, and setup a syscall. Before the shellcode is injected, it is XOR decrypted, meaning the shellcode will not exist in an unencrypted form on disk, only at runtime. The code is designed to be modular and expandable, `utils.h` details a great API with most of the necessary functionality. 

## Output
![image](https://github.com/D3cl4n/Mordor/blob/master/output.png)

The below screenshot shows that the NtAPI functions are not found in the imports of the Mordor.exe file, allowing us to hide better. 

![image](https://github.com/D3cl4n/Mordor/blob/master/output1.png)

## Disclaimer
I am not responsible for how you use these concepts and this code. Only legal, educational uses are condoned, and this project is purely personal (reflects nothing about my professional life). This project was intended for me to learn, and is open source to try and help others learn as well. 
