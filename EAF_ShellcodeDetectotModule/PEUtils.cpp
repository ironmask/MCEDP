#include "PEUtils.h"

/* functions are self explanatory */
PVOID 
PeGetCodeSectionAddress(
	IN PVOID BaseAddress
	)
{
	PIMAGE_OPTIONAL_HEADER  pOptionalHeader;

	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) OPTHDROFFSET(BaseAddress);
	return (PVOID)(pOptionalHeader->BaseOfCode + (ULONG_PTR)BaseAddress);
}

DWORD 
PeGetCodeSectionSize( 
	IN PVOID BaseAddress
	)
{
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;

	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) OPTHDROFFSET(BaseAddress);
	return pOptionalHeader->SizeOfCode;
}

PIMAGE_SECTION_HEADER
PeGetSectionHdrByName (
	IN PVOID BaseAddress,
	IN PCHAR szSection
	)
{
    PIMAGE_SECTION_HEADER psh;
    DWORD nSections;
    DWORD i;

	nSections = NUMOFSECTION(BaseAddress);

	if ((psh = (PIMAGE_SECTION_HEADER) SECHDROFFSET(BaseAddress)) != NULL)
	{
		for ( i = 0 ; i < nSections; i++)
		{
			if (!strcmp ((CHAR *)psh->Name, szSection))
				return psh;
			else
			psh++;
		}
	}

    return NULL;
}

PIMAGE_EXPORT_DIRECTORY  
PeGetExportDirectory( 
	IN PVOID BaseAddress
	)
{
	PIMAGE_OPTIONAL_HEADER poh;
	DWORD VAImageDir;	

    poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET (BaseAddress);
	VAImageDir = (DWORD) poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
   
	return (PIMAGE_EXPORT_DIRECTORY)( (ULONG_PTR)BaseAddress + VAImageDir);
}

PVOID  
PeGetExportDirectoryRVAddress(
	IN PVOID BaseAddress
	)
{
	PIMAGE_OPTIONAL_HEADER poh;

    poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET (BaseAddress);
	return &poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
}