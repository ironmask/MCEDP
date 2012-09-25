#include "LdrList.h"

PPEB
	GetCurrentPeb()
{
    /* In X86 systems , FS:[30] points to PEB */
	return (PPEB)__readfsdword(0x30);
}

STATUS
LdrFindEntryForAddress(
	IN PVOID Address,
    OUT PLDR_DATA_TABLE_ENTRY *TableEntry
	)
{
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY Head, Next;
	PLDR_DATA_TABLE_ENTRY Entry;
	PIMAGE_NT_HEADERS NtHeaders;
	PVOID ImageBase;
	PVOID EndOfImage;

    /* get current process PEB LDR */
	Ldr = GetCurrentPeb()->Ldr;
	if (Ldr == NULL) 
		return MCEDP_STATUS_NO_MORE_ENTRIES;

    /* check the first entry and see if it the Address blong to this module */
    Entry = (PLDR_DATA_TABLE_ENTRY) Ldr->EntryInProgress;
    if (Entry != NULL) {
        NtHeaders = (PIMAGE_NT_HEADERS)NTSIGNATURE( Entry->DllBase);
        if (NtHeaders != NULL) {
            ImageBase = (PVOID)Entry->DllBase;
            EndOfImage = (PVOID)((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage);

            if ((ULONG_PTR)Address >= (ULONG_PTR)ImageBase && (ULONG_PTR)Address < (ULONG_PTR)EndOfImage)
			{
				*TableEntry = Entry;
				return MCEDP_STATUS_SUCCESS;
            }
		}
	}

    /* check "In Memory Order Module List" of loaded modules and seek for requested Address's module */
	Head = &Ldr->InMemoryOrderModuleList;
    Next = Head->Flink;
    while ( Next != Head ) 
	{
        Entry = CONTAINING_RECORD( Next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
		NtHeaders = (PIMAGE_NT_HEADERS)NTSIGNATURE( Entry->DllBase );
        if (NtHeaders != NULL) 
		{
            ImageBase = (PVOID)Entry->DllBase;
            EndOfImage = (PVOID)((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage);

            if ((ULONG_PTR)Address >= (ULONG_PTR)ImageBase && (ULONG_PTR)Address < (ULONG_PTR)EndOfImage) {
				*TableEntry = Entry;
				return MCEDP_STATUS_SUCCESS;
			}
		}

        Next = Next->Flink;
	}
	
	return MCEDP_STATUS_NO_MORE_ENTRIES;
}

STATUS
LdrGetModuleLoadCount( 
	IN PVOID Address,
	OUT PUSHORT LoadCount
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;

    /* find the module */
	if ( LdrFindEntryForAddress( Address, &TableEntry ) == MCEDP_STATUS_NO_MORE_ENTRIES )
		return MCEDP_STATUS_NO_MORE_ENTRIES;

    /* Get the load count */
	*LoadCount = TableEntry->LoadCount;
	return MCEDP_STATUS_SUCCESS;
}


STATUS
LdrLoadListEntry(
	VOID
	)
{
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY Head, Next;
	PLDR_DATA_TABLE_ENTRY Entry;
	PIMAGE_NT_HEADERS NtHeaders;
	PVOID ImageBase;
	PVOID EndOfImage;
	CHAR szAssciModuleName[MAX_MODULE_NAME32];

    /* get current process PEB LDR */
	Ldr = GetCurrentPeb()->Ldr;
	if (Ldr == NULL) 
		return MCEDP_STATUS_NO_MORE_ENTRIES;

    /* Walk "In Memory Order Module List" and simply report them */
	Head = &Ldr->InMemoryOrderModuleList;
    Next = Head->Flink;
    while ( Next != Head ) 
	{
        Entry = CONTAINING_RECORD( Next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
		NtHeaders = (PIMAGE_NT_HEADERS)NTSIGNATURE( Entry->DllBase );
        if (NtHeaders != NULL) 
		{
			SecureZeroMemory(szAssciModuleName, MAX_MODULE_NAME32);
            ImageBase = (PVOID)Entry->DllBase;
            EndOfImage = (PVOID)((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage);
			wcstombs( szAssciModuleName, Entry->BaseDllName.Buffer, Entry->BaseDllName.Length );
			DEBUG_PRINTF(LDBG, NULL, "Module : %-34s | 0x%p -- 0x%p enumerated!\n", szAssciModuleName, ImageBase, EndOfImage);
		}

        Next = Next->Flink;
	}
	
    return MCEDP_STATUS_SUCCESS;
}
