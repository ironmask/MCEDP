#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <time.h>
#include <UrlMon.h>


#define SIZE_OF_NT_SIGNATURE sizeof(IMAGE_NT_SIGNATURE)
#define  NTSIGNATURE(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew))
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + sizeof (IMAGE_FILE_HEADER)))
#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
#define SECHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)))
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + sizeof (IMAGE_FILE_HEADER)))
#define NUMOFSECTION(a) ((DWORD)((PIMAGE_FILE_HEADER) PEFHDROFFSET(a))->NumberOfSections);
#define IsBitSet(val, bit) ((val) & (1 << (bit)))


PVOID 
PeGetCodeSectionAddress(
	IN PVOID BaseAddress
	);

DWORD 
PeGetCodeSectionSize( 
	IN PVOID BaseAddress
	);

PIMAGE_SECTION_HEADER
PeGetSectionHdrByName (
	IN PVOID BaseAddress,
	IN PCHAR szSection
	);

PIMAGE_EXPORT_DIRECTORY  
PeGetExportDirectory( 
	IN PVOID BaseAddress
	);

PVOID  
PeGetExportDirectoryRVAddress(
	IN PVOID BaseAddress
	);