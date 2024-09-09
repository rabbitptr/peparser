#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>

// first version parses itself and only supports x86

// second version parses a binary passed as argument

// third version includes code x64

int main() {

	printf("----PE INFOS----\n");
	
	DWORD_PTR baseAddr = (DWORD_PTR) GetModuleHandle(NULL);

	if (baseAddr == NULL) {
		printf("GetModuleHandle failed with error 0x%X \n", GetLastError());
		return 1;
	}
	
	printf("Module base address: 0x%X \n", baseAddr);

	printf("----DOS HEADER----\n");
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER) baseAddr;

	printf("Dos Header Signature: %s\n", (CHAR*)pDosHdr);
		
	return 0;

}
