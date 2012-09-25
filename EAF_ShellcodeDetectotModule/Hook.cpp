#include "Hook.h"

extern "C" /* ROP detection hooks */
{
	/* static  LPVOID (WINAPI *VirtualAlloc_           )(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc; */
	PVOID VirtualAlloc_ = (PVOID)VirtualAlloc;
	/* static  LPVOID (WINAPI *VirtualAllocEx_         )(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx; */
	PVOID VirtualAllocEx_ = (PVOID)VirtualAllocEx;
	/* static    BOOL (WINAPI *VirtualProtectEx_       )(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtectEx; */
	PVOID VirtualProtectEx_ = (PVOID)VirtualProtectEx;
	/* static    BOOL (WINAPI *VirtualProtect_         )(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtect; */
	PVOID VirtualProtect_ = (PVOID)VirtualProtect;
	/* static  LPVOID (WINAPI *MapViewOfFile_          )(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = MapViewOfFile; */
	PVOID MapViewOfFile_ = (PVOID)MapViewOfFile;
	/* static  LPVOID (WINAPI *MapViewOfFileEx_        )(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) = MapViewOfFileEx; */
	PVOID MapViewOfFileEx_ = (PVOID)MapViewOfFileEx;
	/* static  HANDLE (WINAPI *HeapCreate_			   )(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate; */
	PVOID HeapCreate_ = (PVOID)HeapCreate;
}

STATUS
HookInstall(
	VOID
	)
{

	LONG error;
	CreateProcessInternalW_ = (BOOL (WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE))GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "CreateProcessInternalW");
	DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	/* CreateProcess should be hooked regardless of what type of protection is enabled */
	DetourAttach(&(PVOID&)CreateProcessInternalW_		, HookedCreateProcessInternalW);

    /* Hook virtual memory manipulation function needs for checking rop attacks */
	if ( MCEDP_REGCONFIG.ROP.DETECT_ROP )
	{
		DetourAttach(&(PVOID&)VirtualAlloc_				, HookedVirtualAlloc);
		DetourAttach(&(PVOID&)VirtualAllocEx_			, HookedVirtualAllocEx);
		DetourAttach(&(PVOID&)VirtualProtect_			, HookedVirtualProtect);
		DetourAttach(&(PVOID&)VirtualProtectEx_			, HookedVirtualProtectEx);
		DetourAttach(&(PVOID&)MapViewOfFile_			, HookedMapViewOfFile);
		DetourAttach(&(PVOID&)MapViewOfFileEx_			, HookedMapViewOfFileEx);
		DetourAttach(&(PVOID&)HeapCreate_				, HookedHeapCreate);
	}

    /* Hook CreateThread if ETA_VALIDATION protection is set on */
	if ( MCEDP_REGCONFIG.SHELLCODE.ETA_VALIDATION )
	{
		DetourAttach(&(PVOID&)CreateThread_				, HookedCreateThread);
	}

    /* Hook function we need for loging shellcode activity */
	if ( MCEDP_REGCONFIG.SHELLCODE.ANALYSIS_SHELLCODE )
	{
		DetourAttach(&(PVOID&)URLDownloadToFileW_		, HookedURLDownloadToFileW);
		DetourAttach(&(PVOID&)socket_					, Hookedsocket);
		DetourAttach(&(PVOID&)connect_					, Hookedconnect);
		DetourAttach(&(PVOID&)listen_					, Hookedlisten);
		DetourAttach(&(PVOID&)bind_						, Hookedbind);
		DetourAttach(&(PVOID&)accept_					, Hookedaccept);
		DetourAttach(&(PVOID&)send_						, Hookedsend);
		DetourAttach(&(PVOID&)recv_						, Hookedrecv);
	}

    error = DetourTransactionCommit();
    if (error == NO_ERROR)
	{
		MCEDP_REGCONFIG.PROCESS_HOOKED = TRUE;
		return MCEDP_STATUS_SUCCESS;
	}
	else
	{
		return MCEDP_STATUS_GENERAL_FAIL;
	}
}

STATUS
HookUninstall(
	VOID
	)
{
	CreateProcessInternalW_ = (BOOL (WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE))GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "CreateProcessInternalW");
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	/* Unhooking functions */
	DetourDetach(&(PVOID&)CreateProcessInternalW_		, HookedCreateProcessInternalW);

	if ( MCEDP_REGCONFIG.ROP.DETECT_ROP )
	{
		DetourDetach(&(PVOID&)VirtualAlloc_				, HookedVirtualAlloc);
		DetourDetach(&(PVOID&)VirtualAllocEx_			, HookedVirtualAllocEx);
		DetourDetach(&(PVOID&)VirtualProtect_			, HookedVirtualProtect);
		DetourDetach(&(PVOID&)VirtualProtectEx_			, HookedVirtualProtectEx);
		DetourDetach(&(PVOID&)MapViewOfFile_			, HookedMapViewOfFile);
		DetourDetach(&(PVOID&)MapViewOfFileEx_			, HookedMapViewOfFileEx);
		DetourDetach(&(PVOID&)HeapCreate_				, HookedHeapCreate);
	}

	if ( MCEDP_REGCONFIG.SHELLCODE.ETA_VALIDATION )
	{
		DetourDetach(&(PVOID&)CreateThread_				, HookedCreateThread);
	}

	if ( MCEDP_REGCONFIG.SHELLCODE.ANALYSIS_SHELLCODE )
	{
		DetourDetach(&(PVOID&)CreateThread_				, HookedCreateThread);
		DetourDetach(&(PVOID&)URLDownloadToFileW_		, HookedURLDownloadToFileW);
		DetourDetach(&(PVOID&)socket_					, Hookedsocket);
		DetourDetach(&(PVOID&)connect_					, Hookedconnect);
		DetourDetach(&(PVOID&)listen_					, Hookedlisten);
		DetourDetach(&(PVOID&)bind_						, Hookedbind);
		DetourDetach(&(PVOID&)accept_					, Hookedaccept);
		DetourDetach(&(PVOID&)send_						, Hookedsend);
		DetourDetach(&(PVOID&)recv_						, Hookedrecv);
	}

	DetourTransactionCommit();
	return MCEDP_STATUS_SUCCESS;
}


HANDLE 
WINAPI 
HookedCreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes, 
	SIZE_T dwStackSize, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	LPVOID lpParameter, 
	DWORD dwCreationFlags, 
	LPDWORD lpThreadId
	)
 {
	 HANDLE	hThreadHandle;
	 DWORD dwThreadId;
	 PHWBREAKDATA phd;

	 /* Enable breakpoint for new thread only when shellcode is not detected */
	 if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_NOT_SET )
	 {
		 phd					= (PHWBREAKDATA)LocalAlloc(LMEM_ZEROINIT, sizeof(HWBREAKDATA));
		 phd->Address			= PeGetExportDirectoryRVAddress(GetModuleHandle(MCEDP_REGCONFIG.SHELLCODE.ETAF_MODULE));
		 phd->dwCondition		= HW_ACCESS;				/* Breakpoint type */
		 phd->dwSize			= 4;						/* Breakpoint size */
		 phd->dwThreadStatus	= THREAD_ALREADY_SUSPEND;	/* this means BreakSetup() does't need to suspend thread */

		 /* check bit 2 if is set we have CREATE_SUSPENDED in dwCreationFlags */
		 if ( IsBitSet( dwCreationFlags, 2 ) )  
		 {
			 /* create thread with original dwCreationFlags because it already has CREATE_SUSPENDED bit set! */
			 hThreadHandle = CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, &dwThreadId);

			 if ( lpThreadId != NULL)
				 *lpThreadId = dwThreadId;

			 /* set Thread ID in HWINFO struct and then call BreakSetup() to setup break points for newly created thread */
			 phd->dwThreadId = dwThreadId;
			 DbgThreadSetBreakpoint(phd);

			 if ( phd->dwStatus == DR_ALL_BUSY )
				DEBUG_PRINTF(LDBG, NULL, "All Debug Registers for TID (%p) are busy!\n", dwThreadId);
			 else if ( phd->dwStatus == DR_BREAK_ERROR_UNK )
				DEBUG_PRINTF(LDBG, NULL, "Internal error occurred during TID (%p) DR setting process!\n", dwThreadId);
			 LocalFree(phd);

		 } else 
		 {
			 /* thread is not created in suspend state by default, so we just set the suspend thread bit and call the original CreateThread! */
			 hThreadHandle = CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, &dwThreadId);
		 
			 if ( lpThreadId != NULL)
				 *lpThreadId = dwThreadId;

			 phd->dwThreadId = dwThreadId;
			 DbgThreadSetBreakpoint(phd);

			 if ( phd->dwStatus == DR_ALL_BUSY )
				 DEBUG_PRINTF(LDBG, NULL, "All Debug Registers for TID (%p) are busy!\n", dwThreadId);
			 else if ( phd->dwStatus == DR_BREAK_ERROR_UNK )
				 DEBUG_PRINTF(LDBG, NULL, "Internal error occurred during TID (%p) DR setting process!\n", dwThreadId);

			 /* resume the thread only if it's not created in suspended state by default! */
			 ResumeThread(hThreadHandle);
			 LocalFree(phd);
		 }

		 /* return the thread handler! */
		 return hThreadHandle;
	 }

	 /* shellcode detected, just call the original function */
	 return (CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId));
 }

BOOL
WINAPI
HookedCreateProcessInternalW(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
	)
{
	BOOL bReturn;
	CHAR szDllFullPath[MAX_PATH];

	/* apply config rules if shellcode or ROP detected */
	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET || DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_SET )
	{
		if ( MCEDP_REGCONFIG.SHELLCODE.ANALYSIS_SHELLCODE )
		{
			CHAR *szApplicationNameA = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
			CHAR *szCommandLineA     = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
			PXMLNODE XmlLogNode;
			PXMLNODE XmlIDLogNode;

			if ( lpApplicationName != NULL )
				wcstombs( szApplicationNameA, lpApplicationName, 1024);

			if ( lpCommandLine != NULL )
				wcstombs( szCommandLineA, lpCommandLine, 1024);

			XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
			/* type */
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
			mxmlNewText( XmlLogNode, 0, "1");
			/* exec */
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "exec_process");
			mxmlNewText( XmlLogNode, 0, szApplicationNameA);
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "exec_cmd");
			mxmlNewText( XmlLogNode, 0, szCommandLineA);
			/* save */
			SaveXml( XmlLog );

			LocalFree(szApplicationNameA);
			LocalFree(szCommandLineA);
		}

        /* if malware execution is not allowd then terminate the process */
		if ( MCEDP_REGCONFIG.GENERAL.ALLOW_MALWARE_EXEC == FALSE )
			TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);

        /* let the malware execute */
		return (CreateProcessInternalW_( hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken));
	}
	
	/* if the process is creating with CREATE_SUSPENDED flag, let it do its job */
	if ( IsBitSet(dwCreationFlags, 2) )
	{
		bReturn = CreateProcessInternalW_( hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

		if ( bReturn != FALSE )
		{
           
			strncpy( szDllFullPath, MCEDP_REGCONFIG.MCEDP_MODULE_PATH, MAX_PATH );
			if ( InjectDLLIntoProcess( szDllFullPath, lpProcessInformation->hProcess ) != MCEDP_STATUS_SUCCESS )
			{
				DEBUG_PRINTF(LDBG, NULL, "Module failed to inject itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
				return bReturn;
			}

			DEBUG_PRINTF(LDBG, NULL, "Module injected itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
			/* Sleep for INIT_WAIT_TIME sec and let MCEDP init itself in newly created process
			   TODO : use a messaging mechanism and resume process after init finished instead of sleeping! */
			Sleep(INIT_WAIT_TIME);
			return bReturn;
		}
	} 
	else
	{
		/* if the process is not creating with CREATE_SUSPENDED flag, force it do it */
		bReturn = CreateProcessInternalW_( hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED , lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
		
		if ( bReturn != FALSE )
		{
             /* TODO : We dont need this if ther process is already added into Protection List in registry, so we should remove this lines  */
			strncpy( szDllFullPath, MCEDP_REGCONFIG.MCEDP_MODULE_PATH, MAX_PATH );
			if ( InjectDLLIntoProcess( szDllFullPath, lpProcessInformation->hProcess ) != MCEDP_STATUS_SUCCESS )
			{
				DEBUG_PRINTF(LDBG, NULL, "Module failed to inject itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
				ResumeThread(lpProcessInformation->hThread);
				return bReturn;
			}

			DEBUG_PRINTF(LDBG, NULL, "Module injected itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
			/* Sleep for INIT_WAIT_TIME sec and let MCEDP init itself in newly created process
			   TODO : use a messaging mechanism and resume process after init finished instead of sleeping! */
			Sleep(INIT_WAIT_TIME);
			ResumeThread(lpProcessInformation->hThread);
			return bReturn;
		}
	}

	return bReturn;
}

HRESULT
WINAPI
HookedURLDownloadToFileW(
    LPUNKNOWN pCaller,
    LPCWSTR szURL,
    LPCWSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
	)
{
	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		CHAR *szUrlA			= (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
		CHAR *szFileNameA		= (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;

		if ( szURL != NULL )
			wcstombs( szUrlA, szURL, 1024);

		if ( szFileName != NULL )
			wcstombs( szFileNameA, szFileName, 1024);

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		/* type */
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
		mxmlNewText( XmlLogNode, 0, "2");
		/* download */
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "download_url");
		mxmlNewText( XmlLogNode, 0, (PCHAR)szUrlA);
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "download_filename");
		mxmlNewText( XmlLogNode, 0, (PCHAR)szFileNameA);
		/* save */
		SaveXml( XmlLog );

		if ( MCEDP_REGCONFIG.SHELLCODE.ALLOW_MALWARE_DWONLOAD == FALSE )
			return S_OK;

		LocalFree(szUrlA);
		LocalFree(szFileNameA);
	}

	return (URLDownloadToFileW_( pCaller, szURL, szFileName, dwReserved, lpfnCB));
}

HMODULE 
WINAPI
HookedLoadLibraryExW(
	LPCWSTR lpLibFileName, 
	HANDLE hFile, 
	DWORD dwFlags
	)
{
	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		CHAR *szLibFileNameA = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
		PXMLNODE XmlLogNode;
		PXMLNODE XmlDataNode;

		if ( lpLibFileName != NULL )
			wcstombs( szLibFileNameA, lpLibFileName, 1024);

		XmlLogNode = CreateXmlElement( XmlShellcode, "loadlib");
		XmlDataNode = CreateXmlElement( XmlLogNode, "libname");
		SetTextNode( XmlDataNode, 0, szLibFileNameA);
		SaveXml( XmlLog );

		LocalFree(szLibFileNameA);
	}

	return (LoadLibraryExW_( lpLibFileName, hFile, dwFlags));
}

SOCKET
WSAAPI
Hookedsocket(
	int af,
	int type,
	int protocol
	)
{

	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
		mxmlNewText( XmlLogNode, 0, "3");
		// socket
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "socket_af");
		switch (af) 
		{
		case AF_UNSPEC:
			mxmlNewText( XmlLogNode, 0, "Unspecified");
				break;
		case AF_INET:
			mxmlNewText( XmlLogNode, 0, "AF_INET (IPv4)");
			break;
		case AF_INET6:
			mxmlNewText( XmlLogNode, 0, "AF_INET6 (IPv6)");
			break;
		case AF_NETBIOS:
			mxmlNewText( XmlLogNode, 0, "AF_NETBIOS (NetBIOS)");
			break;
		case AF_BTH:
			mxmlNewText( XmlLogNode, 0, "AF_BTH (Bluetooth)");
			break;
		default:
			mxmlNewText( XmlLogNode, 0, "Other");
			break;
		}

		XmlLogNode = mxmlNewElement( XmlIDLogNode, "socket_type");
		switch (type) 
		{
		case 0:
			mxmlNewText( XmlLogNode, 0, "Unspecified");
			break;
		case SOCK_STREAM:
			mxmlNewText( XmlLogNode, 0, "SOCK_STREAM (stream)");
			break;
		case SOCK_DGRAM:
			mxmlNewText( XmlLogNode, 0, "SOCK_DGRAM (datagram)");
			break;
		case SOCK_RAW:
			mxmlNewText( XmlLogNode, 0, "SOCK_RAW (raw)");
			break;
		case SOCK_RDM:
			mxmlNewText( XmlLogNode, 0, "SOCK_RDM (reliable message datagram)");
			break;
		case SOCK_SEQPACKET:
			mxmlNewText( XmlLogNode, 0, "SOCK_SEQPACKET (pseudo-stream packet)");
			break;
		default:
			mxmlNewText( XmlLogNode, 0, "Other");
			break;
		}

		XmlLogNode = mxmlNewElement( XmlIDLogNode, "socket_protocol");
		switch (protocol)
		{
		case 0:
			mxmlNewText( XmlLogNode, 0, "Unspecified");
			break;
		case IPPROTO_ICMP:
			mxmlNewText( XmlLogNode, 0, "IPPROTO_ICMP (ICMP)");
			break;
		case IPPROTO_IGMP:
			mxmlNewText( XmlLogNode, 0, "IPPROTO_IGMP (IGMP)");
			break;
		case IPPROTO_TCP:
			mxmlNewText( XmlLogNode, 0, "IPPROTO_TCP (TCP)");
			break;
		case IPPROTO_UDP:
			mxmlNewText( XmlLogNode, 0, "IPPROTO_UDP (UDP)");
			break;
		case IPPROTO_ICMPV6:
			mxmlNewText( XmlLogNode, 0, "IPPROTO_ICMPV6 (ICMP Version 6)");
			break;
		default:
			mxmlNewText( XmlLogNode, 0, "Other");
			break;
		}

		// save
		SaveXml( XmlLog );
	}

	return (socket_( af, type, protocol));
}


int
WSAAPI
Hookedconnect(
	SOCKET s,
    const struct sockaddr *name,
	int namelen
    )
{
	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;
		CHAR szPort[20];
		sockaddr_in *sdata;
		sdata = (sockaddr_in *)name;
		
		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
		mxmlNewText( XmlLogNode, 0, "4");
		// connect
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "connect_ip");
		mxmlNewText( XmlLogNode, 0, inet_ntoa(sdata->sin_addr));
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "connect_port");
		mxmlNewText( XmlLogNode, 0, itoa(htons(sdata->sin_port), szPort, 10));
		// save
		SaveXml( XmlLog );
	}

	return (connect_(s, name, namelen));
}


int
WSAAPI
Hookedlisten(
	SOCKET s,
	int backlog
	)
{
	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
		mxmlNewText( XmlLogNode, 0, "5");
		// listen
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "listen_desc");
		mxmlNewText( XmlLogNode, 0, "Shellcode attemp to listen on a port (possibly on previously bind address).");
		// save
		SaveXml( XmlLog );
	}

	return (listen_( s,backlog ));
}


int
WSAAPI
Hookedbind(
  SOCKET s,
  const struct sockaddr *name,
  int namelen
  )
{
	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;
		CHAR szPort[20];
		sockaddr_in *sdata;
		sdata = (sockaddr_in *)name;

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
		mxmlNewText( XmlLogNode, 0, "6");
		// bind
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "bind_ip");
		mxmlNewText( XmlLogNode, 0, inet_ntoa(sdata->sin_addr));
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "bind_port");
		mxmlNewText( XmlLogNode, 0, itoa(htons(sdata->sin_port),szPort, 10));
		// save
		SaveXml( XmlLog );
	}

	return (bind_(s, name, namelen));
}

SOCKET
WSAAPI
Hookedaccept(
	SOCKET s,
	struct sockaddr *addr,
	int *addrlen
	)
{

	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;
		CHAR szPort[20];
		sockaddr_in *sdata;
		sdata = (sockaddr_in *)addr;

		if ( addr != NULL && addrlen != NULL )
		{
			XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
			// type
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
			mxmlNewText( XmlLogNode, 0, "7");
			// accept
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "accept_ip");
			mxmlNewText( XmlLogNode, 0, inet_ntoa(sdata->sin_addr));
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "accept_port");
			mxmlNewText( XmlLogNode, 0, _itoa(htons(sdata->sin_port),szPort, 10));
			// save
			SaveXml( XmlLog );
		}
		else
		{
			XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
			// type
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
			mxmlNewText( XmlLogNode, 0, "7");
			// accept
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "accept_ip");
			mxmlNewText( XmlLogNode, 0, "NULL");
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "accept_port");
			mxmlNewText( XmlLogNode, 0, "NULL");
			// save
			SaveXml( XmlLog );
		}
	}


	return (accept_( s, addr, addrlen ));
}

int
WSAAPI
Hookedsend(
	SOCKET s,
	const char *buf,
	int len,
	int flags
	)
{

	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET )
	{
		CHAR szPort[20];
        CHAR szUID[UID_SIZE];
		sockaddr_in sdata;
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;
		int sock_len = sizeof(sockaddr);

		if ( len > 1 )
		{
			XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
			// type
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
			mxmlNewText( XmlLogNode, 0, "8");
			// send
			getpeername( s, (sockaddr *)&sdata, &sock_len);
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "send_ip");
			mxmlNewText( XmlLogNode, 0, inet_ntoa(sdata.sin_addr));
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "send_port");
			mxmlNewText( XmlLogNode, 0, _itoa(htons(sdata.sin_port), szPort, 10));
			XmlLogNode = mxmlNewElement( XmlIDLogNode, "send_datalen");
			mxmlNewText( XmlLogNode, 0, _itoa(len, szPort, 10));
            XmlLogNode = mxmlNewElement( XmlIDLogNode, "data_uid");
			mxmlNewText( XmlLogNode, 0, GenRandomStr(szUID, UID_SIZE-1));
            HexDumpToFile((PBYTE)buf, len ,szUID);
			// save
			SaveXml( XmlLog );
		}
	}

	return (send_( s, buf, len, flags));
}

int
WSAAPI
Hookedrecv(
	SOCKET s,
	char *buf,
	int len,
	int flags
	)
{

	if ( DbgGetShellcodeFlag() == MCEDP_STATUS_SHELLCODE_FLAG_SET && len > 1)
	{
		CHAR szPort[20];
        CHAR szUID[UID_SIZE];
		sockaddr_in sdata;
		int sock_len = sizeof(sockaddr);
		PXMLNODE XmlLogNode;
		PXMLNODE XmlIDLogNode;
			
		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
		mxmlNewText( XmlLogNode, 0, "9");
		// recv
		getpeername( s, (sockaddr *)&sdata, &sock_len);
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "recv_ip");
		mxmlNewText( XmlLogNode, 0, inet_ntoa(sdata.sin_addr));
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "recv_port");
		mxmlNewText( XmlLogNode, 0, _itoa(htons(sdata.sin_port), szPort, 10));
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "recv_datalen");
		mxmlNewText( XmlLogNode, 0, _itoa(len, szPort, 10));
        XmlLogNode = mxmlNewElement( XmlIDLogNode, "data_uid");
	    mxmlNewText( XmlLogNode, 0, GenRandomStr(szUID, UID_SIZE-1));
        HexDumpToFile((PBYTE)buf, len ,szUID);
		// save
		SaveXml( XmlLog );
	}

	return (recv_( s, buf, len, flags));
}