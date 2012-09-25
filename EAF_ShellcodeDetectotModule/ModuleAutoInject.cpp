#include "ModuleAutoInject.h"

STATUS
InjectDLLIntoProcess(
	IN PCHAR szDllPath,
	IN HANDLE hProcessHandle
	)
{
	HANDLE hRemoteThread;
    LPVOID lpRemoteDllPAth;
	ERRORINFO err;

    lpRemoteDllPAth = VirtualAllocEx( hProcessHandle, 
		                              NULL, 
									  strlen(szDllPath) + 1, 
									  MEM_COMMIT, 
									  PAGE_READWRITE);

	if ( lpRemoteDllPAth == NULL )
	{
		REPORT_ERROR("VirtualAllocEx()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
    }

	if ( WriteProcessMemory( hProcessHandle, 
		                     lpRemoteDllPAth, 
							 szDllPath, 
							 strlen(szDllPath), 
							 NULL) == FALSE ) 
	{
		REPORT_ERROR("WriteProcessMemory()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
    }

    hRemoteThread = CreateRemoteThread( hProcessHandle,
                                        NULL,
                                        0,
							            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA"),
							            lpRemoteDllPAth,
                                        0,
                                        NULL);

	if ( hRemoteThread == NULL )
	{
		REPORT_ERROR("CreateRemoteThread()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	return MCEDP_STATUS_SUCCESS;
}