#pragma once
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
#include<winternl.h>
#include<winnt.h>

PIMAGE_DOS_HEADER printDosHdrData(DWORD_PTR baseAddr);

PIMAGE_NT_HEADERS printNtHdrData(DWORD_PTR baseAddr, PIMAGE_DOS_HEADER pDosHdr);

PIMAGE_FILE_HEADER printFileHdrData(PIMAGE_NT_HEADERS pNtHdr);

PIMAGE_OPTIONAL_HEADER printOptHdrData(DWORD_PTR baseAddr, PIMAGE_NT_HEADERS pNtHdr);

printSectHdrData(DWORD_PTR baseAddr, PIMAGE_OPTIONAL_HEADER pOptHdr, PIMAGE_FILE_HEADER pFileHdr);

