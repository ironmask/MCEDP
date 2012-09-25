#include "RopDetection.h"

BOOL bRopDetected = FALSE;
BOOL bRopLoged = FALSE;

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect
	)
{
	PNT_TIB ThreadInfo;
	
	if ( DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_NOT_SET )
	{
		/* get the thread stack range from TIB. */
		ThreadInfo = (PNT_TIB) __readfsdword( 0x18 );

		/* monitor esp value if we supposed to */
		if ( MCEDP_REGCONFIG.ROP.STACK_MONITOR )
		{
			/* check if thread is passing the actual stack boundaries */
			if ( lpEspAddress < (DWORD)ThreadInfo->StackLimit || lpEspAddress >= (DWORD)ThreadInfo->StackBase ) 
			{
				/* set ROP flags */
				DbgSetRopFlag();
				DEBUG_PRINTF(LDBG,NULL,"ROP Detected by STACK_MONITOR, out of bound stack!\n");
			}
		}

		/* Monitor stack page permission change value if we supposed to */
		if ( MCEDP_REGCONFIG.MEM.STACK_RWX )
		{
			if ( lpAddress > ThreadInfo->StackLimit || lpAddress <= ThreadInfo->StackBase )
			{
				/* if it is going to make the stack executable */
				if ( ( flProtect & PAGE_EXECUTE )           ||  
					 ( flProtect & PAGE_EXECUTE_READWRITE ) || 
					 ( flProtect & PAGE_EXECUTE_READ )      ||
					 ( flProtect & PAGE_EXECUTE_WRITECOPY ) )
				{
					/* set ROP flag */
					DbgSetRopFlag();
					DEBUG_PRINTF(LDBG,NULL,"ROP Detected by STACK_RWX, stack permission changed to be executable!\n");
				}
			}
		}

		if ( MCEDP_REGCONFIG.ROP.PIVOTE_DETECTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( MCEDP_REGCONFIG.ROP.CALL_VALIDATION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( MCEDP_REGCONFIG.ROP.FORWARD_EXECUTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_SET )
		{
			if ( MCEDP_REGCONFIG.ROP.DUMP_ROP )
				DbgReportRop((PVOID)lpEspAddress,RopCallee);

			if ( MCEDP_REGCONFIG.ROP.KILL_ROP)
				TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
		}
	}
}



STATUS
DbgSetRopFlag(
	VOID
	)
{
    ERRORINFO err;

	/* set the ROP flag */
	bRopDetected = TRUE;

    /* init log path */
    if ( InitLogPath( MCEDP_REGCONFIG.LOG_PATH, MAX_PATH ) != MCEDP_STATUS_SUCCESS )
	{
		REPORT_ERROR("InitLogPath()", &err);
		return MCEDP_STATUS_GENERAL_FAIL;
	}

	return MCEDP_STATUS_SHELLCODE_FLAG_SET;
}

STATUS
DbgGetRopFlag(
	VOID
	)
{
	/* get current value of ROP flag */
	if ( bRopDetected )
		return MCEDP_STATUS_ROP_FLAG_SET;

	return MCEDP_STATUS_ROP_FLAG_NOT_SET;
}

STATUS
DbgGetRopModule(
	IN PVOID StackPointerAddress,
	OUT PCHAR ModuleFullName,
	IN DWORD dwSize
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	DWORD ModuleCount = 0;

    /* translate StackPointerAddress to module name */
	if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)StackPointerAddress), &TableEntry) == MCEDP_STATUS_SUCCESS )
	{
		wcstombs( ModuleFullName, TableEntry->FullDllName.Buffer, dwSize );
		return MCEDP_STATUS_SUCCESS;
	} 

	return MCEDP_STATUS_INTERNAL_ERROR;
}

VOID
DbgReportRop(
	IN CONST PVOID Address,
	IN CONST DWORD APINumber
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	LPVOID lpAddress;
	LPVOID lpCodeSectionAddress;
	CHAR szAssciFullModuleName[MAX_MODULE_NAME32];
	CHAR szAssciModuleName[MAX_MODULE_NAME32];
	PCHAR szRopInst;
	DWORD dwCodeSectionSize;
	DWORD i;
	PXMLNODE XmlLogNode;
	PXMLNODE XmlIDLogNode;;

	XmlIDLogNode = CreateXmlElement( XmlShellcode, "row");
    // type
	XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
	mxmlNewText( XmlLogNode, 0, "0");
    // data
	XmlLogNode = CreateXmlElement( XmlIDLogNode, "function");
	SecureZeroMemory(szAssciFullModuleName, MAX_MODULE_NAME32);
	SecureZeroMemory(szAssciModuleName, MAX_MODULE_NAME32);
	szRopInst = (PCHAR)LocalAlloc(LMEM_ZEROINIT, 2048);
	lpAddress = Address;
	bRopDetected = TRUE;

    /* Get function name which reports rop */
	switch (APINumber)
	{
	case CalleeVirtualAlloc:
		SetTextNode( XmlLogNode, 0, "VirtualAlloc");
		break;
	case CalleeVirtualAllocEx:
		SetTextNode( XmlLogNode, 0, "VirtualAllocEx");
		break;
	case CalleeVirtualProtect:
		SetTextNode( XmlLogNode, 0, "VirtualProtect");
		break;
	case CalleeVirtualProtectEx:
		SetTextNode( XmlLogNode, 0, "VirtualProtectEx");
		break;
	case CalleeMapViewOfFile:
		SetTextNode( XmlLogNode, 0, "MapViewOfFile");
		break;
	case CalleeMapViewOfFileEx:
		SetTextNode( XmlLogNode, 0, "MapViewOfFileEx");
		break;
	}

    /* Get the module that used for rop gadgets */
	if ( DbgGetRopModule( lpAddress, szAssciFullModuleName, MAX_MODULE_NAME32) == MCEDP_STATUS_SUCCESS )
	{
		XmlLogNode = CreateXmlElement( XmlIDLogNode, "module");
		SetTextNode( XmlLogNode, 0, szAssciFullModuleName);
		SaveXml( XmlLog );
	}

    /* Dump possible ROP gadgets */
	if ( MCEDP_REGCONFIG.ROP.DUMP_ROP == TRUE )
	{
		lpAddress = (PVOID)((DWORD_PTR)lpAddress - MCEDP_REGCONFIG.ROP.ROP_MEM_FAR);
		for ( i = 0 ; i <= MCEDP_REGCONFIG.ROP.MAX_ROP_MEM ; i++ , lpAddress = (LPVOID)((DWORD)lpAddress + 4) )
		{
			if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)lpAddress), &TableEntry) == MCEDP_STATUS_SUCCESS )
			{
				/* get module name */
				wcstombs( szAssciModuleName, TableEntry->FullDllName.Buffer, TableEntry->FullDllName.Length );

				/* Get module .text section start address */
				if ( ( lpCodeSectionAddress = PeGetCodeSectionAddress( TableEntry->DllBase ) ) == NULL )
				{
					DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [FAILD -- MODULE CODE SECTION ADDRESS NULL]\n", lpAddress, (*(ULONG_PTR *)lpAddress));
					break;
				}

				/* Get module .text section size */
				if ( ( dwCodeSectionSize = PeGetCodeSectionSize( TableEntry->DllBase ) ) == NULL )
				{
					DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [FAILD - MODULE CODE SECTION SIZE NULL]\n", lpAddress, (*(ULONG_PTR *)lpAddress));
					break;
				}

				/* Check if instruction lies inside the .text section */
				if ( (*(ULONG_PTR *)lpAddress) >= (ULONG_PTR)lpCodeSectionAddress && (*(ULONG_PTR *)lpAddress) < ( (ULONG_PTR)lpCodeSectionAddress + dwCodeSectionSize ) )
				{

					if ( ShuDisassmbleRopInstructions( (PVOID)(*(ULONG_PTR *)lpAddress), szRopInst, MCEDP_REGCONFIG.ROP.MAX_ROP_INST ) == MCEDP_STATUS_SUCCESS )
					{
						DEBUG_PRINTF(LROP, NULL, "[ 0x%p ] %s + 0x%p :\n", (*(ULONG_PTR *)lpAddress), szAssciModuleName, (*(ULONG_PTR *)lpAddress - (ULONG_PTR)TableEntry->DllBase));
						DEBUG_PRINTF(LROP, NULL, "%s", szRopInst);
					} else
					{
						DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [FAILD TO DISASSMBLE]\n", lpAddress, (*(ULONG_PTR *)lpAddress));
					}

					SecureZeroMemory(szRopInst, 2048);

				} else
					DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [OUT OF CODE SECTION]\n", lpAddress, (*(ULONG_PTR *)lpAddress));

			} else
				DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p\n", lpAddress, (*(ULONG_PTR *)lpAddress));
		}
	}

	LocalFree(szRopInst);
}