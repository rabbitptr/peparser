#include"funcparser.h"


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
	
	printf("\tModule base address: 0x00%X \n", baseAddr);

	PIMAGE_DOS_HEADER pDosHdr = printDosHdrData(baseAddr);

	PIMAGE_NT_HEADERS pNtHdr = printNtHdrData(baseAddr,pDosHdr);

	PIMAGE_FILE_HEADER pFileHdr =  printFileHdrData(pNtHdr);

	PIMAGE_OPTIONAL_HEADER pOptHdr = printOptHdrData(baseAddr, pNtHdr);

	printSectHdrData(baseAddr, pOptHdr, pFileHdr);

	return 0;

}
