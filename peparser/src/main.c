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
	
	printf("\tModule base address: 0x00%X \n", baseAddr);

	printf("----DOS HEADER----\n");
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER) baseAddr;

	printf("\tDos Header Signature: %s\n", (CHAR*)pDosHdr);

	printf("----IMAGE NT HEADER----\n");

	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(baseAddr + pDosHdr->e_lfanew);

	printf("\tPE Header Signature: %s\n", (CHAR*)pNtHdr);

	printf("----IMAGE FILE HEADER----\n");

	PIMAGE_FILE_HEADER pFileHdr = (PIMAGE_FILE_HEADER)&pNtHdr->FileHeader;

	printf("\tCPU type: 0x%X\n", pFileHdr->Machine);
	printf("\tNumber of sections: %d\n", pFileHdr->NumberOfSections);
	printf("\tCharacteristics: 0x%X\n", pFileHdr->Characteristics);

	printf("----IMAGE OPTIONAL HEADER----\n");

	PIMAGE_OPTIONAL_HEADER pOptHdr = (PIMAGE_OPTIONAL_HEADER)&pNtHdr->OptionalHeader;

	printf("\tAddress of entry point: 0x00%X\n", (baseAddr + pOptHdr->AddressOfEntryPoint));
	printf("\tImage Base: 0x00%X\n", pOptHdr->ImageBase);

	printf("----IMAGE SECTION HEADER----\n");

	PIMAGE_SECTION_HEADER pCurSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pOptHdr + pFileHdr->SizeOfOptionalHeader);

	for (size_t i = 0; i < pFileHdr->NumberOfSections; i++) {
		printf("\t %s:\n", (CHAR*)pCurSection->Name);
		printf("\t\t Virtual Address: 0x00%X\n", (baseAddr + pCurSection->VirtualAddress));
		printf("\t\t Virtual Size: 0x%X\n", (pCurSection->Misc.VirtualSize));
		printf("\t\t Physical Address: 0x00%X\n", (baseAddr + pCurSection->Misc.PhysicalAddress));
		printf("\t\t Physical Size: 0x%X\n", (pCurSection->SizeOfRawData));
		pCurSection++;
	}

	return 0;

}
