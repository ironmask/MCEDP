#include "ProcIPC.h"

STATUS
GetOperationData(
	IN CHAR* szDirectory,
	IN POPDATA pOperationData
	)
{
	HANDLE hMapFile;
	POPDATA pOpData;
	CHAR szSharedMemName[MAX_PATH];
	ERRORINFO err;

	SecureZeroMemory( szSharedMemName, MAX_PATH);
	strncat( szSharedMemName, "Local\\", MAX_PATH);
	strncat( szSharedMemName, SHARED_MEM_PERFIX, MAX_PATH);
	strncat( szSharedMemName, szDirectory, MAX_PATH);

	hMapFile = OpenFileMapping( FILE_MAP_ALL_ACCESS,
		                        FALSE,
                                szSharedMemName);

	if ( hMapFile == NULL )
	{
		REPORT_ERROR( "OpenFileMapping()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	pOpData = (POPDATA) MapViewOfFile( hMapFile,
		                               FILE_MAP_ALL_ACCESS,
									   0,
									   0,
									   sizeof(OPDATA));

	if ( pOpData == NULL )
	{
		REPORT_ERROR( "MapViewOfFile()", &err);
		CloseHandle(hMapFile);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	memcpy( pOperationData, pOpData, sizeof(OPDATA));
	CloseHandle(hMapFile);
	return MCEDP_STATUS_SUCCESS;
}

STATUS
GetProcessCreateTime( 
	IN HANDLE hProcess,
	OUT PLARGE_INTEGER CreateTime
	)
{
	NtQueryInformationProcess_ NtQueryInformationProcess;
	PKERNEL_USER_TIMES ProcessTime;
	ERRORINFO err;

	ProcessTime = (PKERNEL_USER_TIMES)LocalAlloc( LMEM_ZEROINIT, sizeof( KERNEL_USER_TIMES ));
	NtQueryInformationProcess = (NtQueryInformationProcess_)GetProcAddress( GetModuleHandle("NTDLL"), "NtQueryInformationProcess" );

	if ( NtQueryInformationProcess == NULL )
	{
		REPORT_ERROR( "GetProcAddress()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	if ( NtQueryInformationProcess( hProcess, PROCESS_TIME, ProcessTime, sizeof( KERNEL_USER_TIMES ), NULL ) != STATUS_SUCCESS )
	{
		REPORT_ERROR( "NtQueryInformationProcess()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	*CreateTime = ProcessTime->CreateTime;
	return MCEDP_STATUS_SUCCESS;
}

// TODO : need mutex for over process sync
STATUS
SetOperationData(
	IN PCHAR szDirectory,
	IN POPDATA pOperationData,
	IN DWORD dwFlags
	)
{
	HANDLE hMapFile;
	POPDATA pOpData;
	CHAR szSharedMemName[MAX_PATH];
	ERRORINFO err;

	SecureZeroMemory( szSharedMemName, MAX_PATH);
	strncat( szSharedMemName, "Local\\", MAX_PATH);
	strncat( szSharedMemName, SHARED_MEM_PERFIX, MAX_PATH);
	strncat( szSharedMemName, szDirectory, MAX_PATH);

	hMapFile = OpenFileMapping( FILE_MAP_ALL_ACCESS,
		                        FALSE,
                                szSharedMemName);

	if ( hMapFile == NULL )
	{
		REPORT_ERROR( "OpenFileMapping()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	pOpData = (POPDATA)MapViewOfFile( hMapFile,
			                          FILE_MAP_ALL_ACCESS, 
									  0,
									  0, 
									  sizeof(OPDATA));

	if ( pOpData == NULL)
	{
		REPORT_ERROR( "MapViewOfFile()", &err);
		CloseHandle(hMapFile);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	if ( IsBitSet( dwFlags, 31 ) ) // IPC_APP_TYPE
	{
		strncpy( pOpData->szAppType, pOperationData->szAppType, MAX_CONFIG_STR );
	} 
	if ( IsBitSet( dwFlags, 30 ) ) // IPC_APP_PATH
	{
		strncpy( pOpData->szAppPath, pOperationData->szAppPath, MAX_PATH );
	}
	if ( IsBitSet( dwFlags, 29 ) ) // IPC_OP_DIR
	{
		strncpy( pOpData->szOPDir, pOperationData->szOPDir, MAX_PATH );
	}
	if ( IsBitSet( dwFlags, 28 ) ) // IPC_STATUS
	{
		pOpData->dwStatus = pOperationData->dwStatus;
	}
	if ( IsBitSet( dwFlags, 27 ) ) // IPC_START_TIME
	{
		memcpy( &pOpData->StartTime, &pOperationData->StartTime, sizeof(LARGE_INTEGER));
	}
	if ( IsBitSet( dwFlags, 28 ) ) // IPC_OP_PID
	{
		memcpy( pOpData->OperationPID, pOperationData->OperationPID, sizeof(OPPID) * MAX_OP_PID);
	}
	if ( IsBitSet( dwFlags, 28 ) ) // IPC_OUTPUT_DIR
	{
		strncpy( pOpData->szOutputDir, pOperationData->szOutputDir, MAX_PATH);
	}

	CloseHandle( hMapFile );
	return MCEDP_STATUS_SUCCESS;
}

STATUS
GetCurrentOperationDir(
	OUT PCHAR szOpDir,
	IN DWORD dwSize
	)
{
	ERRORINFO err;
	CHAR szModuleFullPath[MAX_PATH];
	PCHAR Dir;

	if ( GetModuleFileName( hGlobalDllHandle, szModuleFullPath, MAX_PATH ) == 0 )
	{
		REPORT_ERROR("GetModuleFileName()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	if ( Dir = strrchr( szModuleFullPath, '\\' ) )
	{
		*Dir = '\0';
		if ( Dir = strrchr( szModuleFullPath, '\\' ) )
		{
			strncpy( szOpDir, Dir+1, dwSize);
			return MCEDP_STATUS_SUCCESS;
		}
	}
}

