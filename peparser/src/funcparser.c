#pragma once
#include"funcparser.h"

PIMAGE_DOS_HEADER printDosHdrData(DWORD_PTR baseAddr) {
	printf("----DOS HEADER----\n");
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)baseAddr;

	printf("\tDos Header Signature: %s\n", (CHAR*)pDosHdr);

	return pDosHdr;
}

PIMAGE_NT_HEADERS printNtHdrData(DWORD_PTR baseAddr, PIMAGE_DOS_HEADER pDosHdr) {
	printf("----IMAGE NT HEADER----\n");
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(baseAddr + pDosHdr->e_lfanew);
	printf("\tPE Header Signature: %s\n", (CHAR*)pNtHdr);

	return pNtHdr;
}

PIMAGE_FILE_HEADER printFileHdrData(PIMAGE_NT_HEADERS pNtHdr) {

	printf("----IMAGE FILE HEADER----\n");
	PIMAGE_FILE_HEADER pFileHdr = (PIMAGE_FILE_HEADER)&pNtHdr->FileHeader;

	printf("\tCPU type: 0x%X\n", pFileHdr->Machine);
	printf("\tNumber of sections: %d\n", pFileHdr->NumberOfSections);
	printf("\tCharacteristics: 0x%X\n", pFileHdr->Characteristics);

	return pFileHdr;
}

PIMAGE_OPTIONAL_HEADER printOptHdrData(DWORD_PTR baseAddr, PIMAGE_NT_HEADERS pNtHdr) {
	printf("----IMAGE OPTIONAL HEADER----\n");
	PIMAGE_OPTIONAL_HEADER pOptHdr = (PIMAGE_OPTIONAL_HEADER)&pNtHdr->OptionalHeader;

	printf("\tAddress of entry point: 0x00%X\n", (baseAddr + pOptHdr->AddressOfEntryPoint));
	printf("\tImage Base: 0x00%X\n", pOptHdr->ImageBase);

	return pOptHdr;
}

printSectHdrData(DWORD_PTR baseAddr, PIMAGE_OPTIONAL_HEADER pOptHdr, PIMAGE_FILE_HEADER pFileHdr) {
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
}