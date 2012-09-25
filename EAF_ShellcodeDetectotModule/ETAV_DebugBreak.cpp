#include "ETAV_DebugBreak.h"
#include "LdrList.h"
#include "XmlLog.h"

BOOL bShellcodeDetected = FALSE;
PXMLNODE XmlLog;
PXMLNODE XmlShellcode;

LONG 
CALLBACK 
DbgExceptionHandler(
	PEXCEPTION_POINTERS ExceptionInfo
	)
{
	static DWORD dwEaAccessCount = 0;
	CHAR szModuleName[MAX_MODULE_NAME32];
	DWORD dwCurrentThreadId =  GetCurrentThreadId();
	STATUS status;

	/* If exception code is STATUS_SINGLE_STEP, it caused by access to export table */
	if ( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
	{
		/* If shellcode already detected , no more validation require */
		if ( DbgGetShellcodeFlag() != MCEDP_STATUS_SHELLCODE_FLAG_SET )
		{
			/* Validate access to export table */
			status = DbgValidateExportTableAccess( ExceptionInfo->ExceptionRecord->ExceptionAddress, szModuleName );

			switch( status )
			{

			/* Error occurred during validation process */
			case MCEDP_STATUS_INTERNAL_ERROR:
				DEBUG_PRINTF(LDBG, NULL, "Accessing EA @%p (cant validate access du to internal error) | TID : 0x%p\t-- Count(%d)!\n",ExceptionInfo->ExceptionRecord->ExceptionAddress, dwCurrentThreadId, dwEaAccessCount);
				break;

			/* Access is valid ( by a loaded module ) */
			case MCEDP_STATUS_VALID_ACCESS:
				DEBUG_PRINTF(LDBG, NULL, "Accessing EA @%p (%s) | TID : 0x%p\t-- Count(%d)!\n",ExceptionInfo->ExceptionRecord->ExceptionAddress, szModuleName, dwCurrentThreadId, dwEaAccessCount);
				break;

			/* Invalid access to FILTER_MODULE export table, probably by a shellcode */
			case MCEDP_STATUS_INVALID_ACCESS:
				/* Report detection of shellcode */
				DEBUG_PRINTF(LDBG, NULL, "Accessing EA @%p (UNKNOWN MODULE - POSSIBLE SHELLCODE) | TID : 0x%p\t-- Count(%d)!\n",ExceptionInfo->ExceptionRecord->ExceptionAddress, dwCurrentThreadId, dwEaAccessCount);
				
				/* Set shellcode detection flags */
				if ( DbgSetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
					DEBUG_PRINTF(LDBG, NULL, "Shellcode flag set successfully!\n");

				/* If KILL_SHELLCODE is set, terminate process without any further shellcode analysis */
				if ( MCEDP_REGCONFIG.SHELLCODE.KILL_SHELLCODE )
					TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);

				/* If DEUMP_SHELLCODE is set, dump raw (binary) and dissembled shellcode in log directory */
				if ( MCEDP_REGCONFIG.SHELLCODE.DUMP_SHELLCODE )
					ShuDumpShellcode(ExceptionInfo->ExceptionRecord->ExceptionAddress);

				/*
				//Disable Export Table Address Filtering for all running threads.
				if ( DbgDisableExportAddressFiltering() != MCEDP_STATUS_SUCCESS )
				{
					DEBUG_PRINTF("EAF failed to disable protection...\n");
				}
				*/
				break;

			}
		}

		/* Export Table access count++ */
		dwEaAccessCount++;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	/* Exception is not caused by a Hardware Breakpoint, so let other exception handlers handle it */
	return EXCEPTION_CONTINUE_SEARCH;
}

STATUS 
DbgThreadSetBreakpoint(
	IN PHWBREAKDATA BreakpointData
	)
{
	HANDLE hThread;
	DWORD dwDebugRegister;
	CONTEXT	ctxThreadContext = {0};
	ERRORINFO err;
	CHAR szBreakType[20] = {'\0'};
	ctxThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	/* Open thread with desired access */
	hThread = OpenThread( THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME , 
		                   FALSE, 
						   BreakpointData->dwThreadId);
	if ( hThread == NULL )
	{
		REPORT_ERROR("OpenThread()", &err);
		/* Set the Error Flag to proper value */
		BreakpointData->dwStatus = DR_BREAK_ERROR_UNK; 
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	/* Is thread already suspend ? */
	if ( BreakpointData->dwThreadStatus != THREAD_ALREADY_SUSPEND )
	{
		/* Suspend thread for getting/setting thread context in a safe manner */
		if ( SuspendThread(hThread) == -1 )
		{
			REPORT_ERROR("SuspendThread()",&err);
			BreakpointData->dwStatus = DR_BREAK_ERROR_UNK;
			return MCEDP_STATUS_INTERNAL_ERROR;

		}
	}
	
	/* Get thread current context */
	if ( !GetThreadContext(hThread,&ctxThreadContext) )
	{
		REPORT_ERROR("GetThreadContext()",&err);
		BreakpointData->dwStatus = DR_BREAK_ERROR_UNK;
		return MCEDP_STATUS_INTERNAL_ERROR;
	}
	
	/* check if Dr(n) is busy with another Hardware Breakpoint? */
	if ( !IsBitSet(ctxThreadContext.Dr7,0) || !IsBitSet(ctxThreadContext.Dr7,1) )
	{
		/* Set the Debug Register */
		dwDebugRegister = 0;
		/* Set the breakpoint address */
		ctxThreadContext.Dr0 = (DWORD)BreakpointData->Address;
		/* Set Dr(n) state as a busy register, it can be use for removing specific breakpoint */
		BreakpointData->dwDrBusyRemove = dwDebugRegister;

	} else if ( !IsBitSet(ctxThreadContext.Dr7,2) || !IsBitSet(ctxThreadContext.Dr7,3) )
	{
		dwDebugRegister = 1;
		ctxThreadContext.Dr1 = (DWORD)BreakpointData->Address;
		BreakpointData->dwDrBusyRemove = dwDebugRegister;

	} else if ( !IsBitSet(ctxThreadContext.Dr7,4) || !IsBitSet(ctxThreadContext.Dr7,5) )
	{
		dwDebugRegister = 2;
		ctxThreadContext.Dr2 = (DWORD)BreakpointData->Address;
		BreakpointData->dwDrBusyRemove = dwDebugRegister;

	} else if ( !IsBitSet(ctxThreadContext.Dr7,6) || !IsBitSet(ctxThreadContext.Dr7,7) )
	{
		dwDebugRegister = 3;
		ctxThreadContext.Dr3 = (DWORD)BreakpointData->Address;
		BreakpointData->dwDrBusyRemove = dwDebugRegister;

	} else 
	{
		/* All Debug Registers are busy */
		BreakpointData->dwStatus = DR_ALL_BUSY;
		return MCEDP_STATUS_GENERAL_FAIL;
	}

	/* Set the proper bit in Dr7 for used Debug Register and Breakpoint type */
	ctxThreadContext.Dr7 |= 1 << (dwDebugRegister * 2);
	ctxThreadContext.Dr7 |= BreakpointData->dwCondition << ((dwDebugRegister * 4) + 16);
	ctxThreadContext.Dr7 |= 1 << ((dwDebugRegister * 4) + 18);

	/* Enable the Breakpoint for thread by setting the thread context */
	if ( !SetThreadContext(hThread,&ctxThreadContext) )
	{
		REPORT_ERROR("GetThreadContext()",&err);
		BreakpointData->dwStatus = DR_BREAK_ERROR_UNK;
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	BreakpointData->dwStatus = DR_BREAK_SET;
	switch ( BreakpointData->dwCondition )
	{
	case HW_ACCESS:
		strncpy( szBreakType, HW_ACCESS_STR, 20);
		break;
	case HW_EXECUTE:
		strncpy( szBreakType, HW_EXECUTE_STR, 20);
		break;
	case HW_WRITE:
		strncpy( szBreakType, HW_WRITE_STR, 20);
		break;
	}

	DEBUG_PRINTF(LDBG, NULL, "Breakpoint On | TID : %p - Dr%d - Len : %d - Condition : %s!\n", BreakpointData->dwThreadId , dwDebugRegister, BreakpointData->dwSize , szBreakType);
	
	/* Resume the thread if it was not in suspend state at creation time */
	if ( BreakpointData->dwThreadStatus != THREAD_ALREADY_SUSPEND )
		ResumeThread(hThread);
	return MCEDP_STATUS_SUCCESS;
}

STATUS
DbgEnableExportAddressFiltering(
	VOID
	)
{
	DWORD dwCurrentPid; 
	HANDLE hThreadSnap;
	HANDLE hBreakThread;
	THREADENTRY32 te32;
	ERRORINFO err;
	PHWBREAKDATA phd;
	
	/* Get current Process Id and initialize the PHWBREAKDATA structure. */
	dwCurrentPid		= GetCurrentProcessId();
	phd					= (PHWBREAKDATA)LocalAlloc(LMEM_ZEROINIT, sizeof(HWBREAKDATA));
	phd->Address		= PeGetExportDirectoryRVAddress(GetModuleHandle(MCEDP_REGCONFIG.SHELLCODE.ETAF_MODULE));
	phd->dwCondition	= HW_ACCESS;	/* Breakpoint Type */
	phd->dwSize			= 4;			/* Breakpoint size */
	phd->dwThreadStatus	= 0;			
	te32.dwSize			= sizeof(te32);
	
	/* Get a snapshot of all running threads ( from all process ) */
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwCurrentPid);
	if ( hThreadSnap == NULL )
	{
		REPORT_ERROR("CreateToolhelp32Snapshot", &err);
		LocalFree(phd);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	if(!Thread32First(hThreadSnap, &te32)) 
	{
		REPORT_ERROR("Thread32First", &err);
		LocalFree(phd);
		CloseHandle(hThreadSnap);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	do 
	{
		/* If thread belongs to our process... */
		if ( te32.th32OwnerProcessID == dwCurrentPid ) 
		{
			/* Create another thread for safely setting Breakpoints. */
			phd->dwThreadId = te32.th32ThreadID;
			hBreakThread = CreateThread( NULL, 
				                         0, 
										 (LPTHREAD_START_ROUTINE)DbgThreadSetBreakpoint, 
										 phd, 
										 0, 
										 NULL);
			WaitForSingleObject( hBreakThread, INFINITE);

			/* report possible errors */
			if ( phd->dwStatus == DR_ALL_BUSY )
				DEBUG_PRINTF(LDBG, NULL, "All Debug Registers for TID (%p) are busy!\n", te32.th32ThreadID);
			else if ( phd->dwStatus == DR_BREAK_ERROR_UNK )
				DEBUG_PRINTF(LDBG, NULL, "Internal error occurred during TID (%p) DR setting process!\n", te32.th32ThreadID);
		}
	} while(Thread32Next(hThreadSnap, &te32)); 

	LocalFree(phd);
	return MCEDP_STATUS_SUCCESS;
}

STATUS
DbgDisableExportAddressFiltering(
	VOID
	)
{
	DWORD dwCurrentPid; 
	DWORD dwThreadId;
	HANDLE hThreadSnap;
	HANDLE hRemoveBreakThread;
	THREADENTRY32 te32;
	ERRORINFO err;
	STATUS status;

	dwCurrentPid = GetCurrentProcessId();
	te32.dwSize	 = sizeof(te32);

	/* Get a snapshot of all running threads ( from all process ) */
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwCurrentPid);
	if ( hThreadSnap == NULL )
	{
		REPORT_ERROR("CreateToolhelp32Snapshot", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	if(!Thread32First(hThreadSnap, &te32)) 
	{
		REPORT_ERROR("Thread32First", &err);
		CloseHandle(hThreadSnap);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	do 
	{
		/* If thread belongs to our process... */
		if ( te32.th32OwnerProcessID == dwCurrentPid ) 
		{
			/* Create another thread for safely removing Breakpoints */
			dwThreadId = te32.th32ThreadID;
			hRemoveBreakThread = CreateThread( NULL, 
				                               0, 
										       (LPTHREAD_START_ROUTINE)DbgThreadUnSetBreakpoint, 
										       &dwThreadId, 
										       0, 
										       NULL);

			WaitForSingleObject( hRemoveBreakThread, INFINITE);
			GetExitCodeThread( hRemoveBreakThread, &status );

			if ( status != MCEDP_STATUS_SUCCESS )
				DEBUG_PRINTF(LDBG, NULL, "EAF fail do remove breakpoints from TID : %p", dwThreadId);
		}
	} while(Thread32Next(hThreadSnap, &te32)); 

	return MCEDP_STATUS_SUCCESS;
}

STATUS
DbgValidateExportTableAccess(
	IN PVOID Address,
	OUT PCHAR tszModuleName
	)
{

	PLDR_DATA_TABLE_ENTRY TableEntry;
	LPVOID lpCodeSectionAddress;
	DWORD dwCodeSectionSize;
	CHAR szAssciModuleName[MAX_MODULE_NAME32] = {'\0'};

	/* find module in LDR module list */
	if ( LdrFindEntryForAddress( Address, &TableEntry ) == MCEDP_STATUS_NO_MORE_ENTRIES )
		return MCEDP_STATUS_INVALID_ACCESS;

	/* Get module .text section start address */
	if ( ( lpCodeSectionAddress = PeGetCodeSectionAddress( TableEntry->DllBase ) ) == NULL )
		return MCEDP_STATUS_INTERNAL_ERROR;

	/* Get module .text section size */
	if ( ( dwCodeSectionSize = PeGetCodeSectionSize( TableEntry->DllBase ) ) == NULL )
		return MCEDP_STATUS_INTERNAL_ERROR;

	/* Check if instruction which accessed Export Table belong to any loaded module ? */
	if ( (ULONG_PTR)Address >= (ULONG_PTR)lpCodeSectionAddress && (ULONG_PTR)Address < ( (ULONG_PTR)lpCodeSectionAddress + dwCodeSectionSize ) )
	{
		wcstombs( szAssciModuleName, TableEntry->FullDllName.Buffer, TableEntry->FullDllName.Length );
		strncpy( tszModuleName, szAssciModuleName, MAX_MODULE_NAME32);
		/* Access caused by a valid module */
		return MCEDP_STATUS_VALID_ACCESS; 
	}

	/* Address dos not belong to any loaded module, so access is invalid! */
	return MCEDP_STATUS_INVALID_ACCESS;
}

STATUS 
DbgThreadUnSetBreakpoint(
	IN PDWORD pdwThreadId
	)
{
	HANDLE hThread;
	CONTEXT	ctxThreadContext = {0};
	ERRORINFO err;

	ctxThreadContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	/* Open thread with desired access */
	hThread = OpenThread( THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME , 
		                   FALSE, 
						   *pdwThreadId);
	if ( hThread == NULL )
	{
		REPORT_ERROR("OpenThread()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	/* Suspend thread for getting/setting thread context in a safe manner */
	if ( SuspendThread(hThread) == -1 )
	{
			REPORT_ERROR("SuspendThread()",&err);
			return MCEDP_STATUS_INTERNAL_ERROR;
	}

	/* Get thread current context */
	if ( !GetThreadContext(hThread,&ctxThreadContext) )
	{
		REPORT_ERROR("GetThreadContext()",&err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	/* erase all hardware breakpoints for this thread */
	ctxThreadContext.Dr7 = 0x00000000;
	ctxThreadContext.Dr0 = 0x00000000;
	ctxThreadContext.Dr1 = 0x00000000;
	ctxThreadContext.Dr2 = 0x00000000;
	ctxThreadContext.Dr3 = 0x00000000;

	/* Set thread context back */
	if ( !SetThreadContext(hThread,&ctxThreadContext) )
	{
		REPORT_ERROR("GetThreadContext()",&err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	DEBUG_PRINTF(LDBG, NULL, "Breakpoints erased | TID : %p !\n", *pdwThreadId);
	ResumeThread(hThread);
	return MCEDP_STATUS_SUCCESS;
}

STATUS
DbgSetShellcodeFlag(
	VOID
	)
{
    ERRORINFO err;

	/* set the shellcode flag */
	bShellcodeDetected = TRUE;

    /* init log path */
    if ( InitLogPath( MCEDP_REGCONFIG.LOG_PATH, MAX_PATH ) != MCEDP_STATUS_SUCCESS )
	{
		REPORT_ERROR("InitLogPath()", &err);
		return MCEDP_STATUS_GENERAL_FAIL;
	}

	return MCEDP_STATUS_SHELLCODE_FLAG_SET;
}

STATUS
DbgGetShellcodeFlag(
	VOID
	)
{
	/* get current value of shellcode flag */
	if ( bShellcodeDetected )
		return MCEDP_STATUS_SHELLCODE_FLAG_SET;

	return MCEDP_STATUS_SHELLCODE_FLAG_NOT_SET;
}