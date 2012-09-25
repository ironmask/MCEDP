/*
    MCEDP is a Client side High Interaction Honeypot
    Developed by  Shahriyar Jalayeri ( Shahriyar.j {at} gmail {dot}  com )
    www.irhoneynet.org
    twitter.com/ponez
*/

#include "Hook.h"
#include "ParsConfig.h"
#include "PacketDump.h"
#include "LogInfo.h"
#include "ETAV_DebugBreak.h"
#include "GeneralProtections.h"
#include "Hash.h"
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

MCEDPREGCONFIG MCEDP_REGCONFIG;
extern PXMLNODE XmlLog;
extern PXMLNODE XmlShellcode;

STATUS
SetupShellcodeDetector(
	VOID
	);

BOOL
APIENTRY
DllMain( 
	HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
	)
{
	BYTE AppFullNameHash[MAX_HASH_SIZE];
	CHAR szAppFullNameHash[MAX_PATH];
	CHAR szAppFullName[MAX_PATH];
	DWORD dwAppFullNameHashValueSize = MAX_HASH_SIZE;
	HANDLE hDetectorThread;
	ERRORINFO err;

	if ( ul_reason_for_call == DLL_PROCESS_ATTACH )
	{

		/* get module full name, we need it for initializing config */
		if ( !GetModuleFileName( NULL, szAppFullName, MAX_PATH ) )
		{
			DEBUG_PRINTF(LDBG, NULL, "GetModuleBaseName() faild!\n");
			return FALSE; /* MCEDP_STATUS_INTERNAL_ERROR */
		}

		if ( GetSHA1Hash( (PBYTE)strtolow(szAppFullName), strlen(szAppFullName), AppFullNameHash, &dwAppFullNameHashValueSize ) != MCEDP_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "GetSHA1Hash() faild!\n");
			return FALSE; /* MCEDP_STATUS_INTERNAL_ERROR */
		}

		/* read and parse the config from registry */
		if ( ParsRegConfig( &MCEDP_REGCONFIG, HashToStr( AppFullNameHash, dwAppFullNameHashValueSize, szAppFullNameHash, MAX_PATH) , MAX_MODULE_NAME32 ) != MCEDP_STATUS_SUCCESS )
		{
			REPORT_ERROR("ParsRegConfig()", &err);
			return FALSE; /* MCEDP_STATUS_INTERNAL_ERROR */
		}

		/* only init targeted process otherwise unload DLL from process address space. */
		if ( stricmp(szAppFullName, MCEDP_REGCONFIG.APP_PATH ) )
		{
			return FALSE;
		}

		hDetectorThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)SetupShellcodeDetector, NULL, 0, NULL);
		if ( hDetectorThread != NULL )
		{
			DEBUG_PRINTF(LDBG, NULL, "Shellcode Detector thread started!\n");
		}
	} 
	else if ( ul_reason_for_call == DLL_PROCESS_DETACH )
	{
		/* Disable Export Table Address Filtering for all running threads. */
		/*
		if ( DbgDisableExportAddressFiltering() != MCEDP_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "EAF failed to disable protection...\n");
		}
		*/

		/* unhook functions */
		if ( MCEDP_REGCONFIG.PROCESS_HOOKED )
			HookUninstall();
	}

	return TRUE;
}

STATUS
SetupShellcodeDetector(
	VOID
	)
{
	ERRORINFO err;

	/* creating XML */
	XmlLog = NewXmlRoot("1.0");
	XmlShellcode = CreateXmlElement(XmlLog, "shellcode");

	/* check if we should delay the protection init */
	if ( MCEDP_REGCONFIG.INIT_DELAY > 0 )
	{
		/* Sleep for INIT_DELAY seconds */
		Sleep(MCEDP_REGCONFIG.INIT_DELAY * SEC );
	}

	/* init log path 
	if ( InitLogPath( MCEDP_REGCONFIG.LOG_PATH, MAX_PATH ) != MCEDP_STATUS_SUCCESS )
	{
		REPORT_ERROR("InitLogPath()", &err);
		return MCEDP_STATUS_GENERAL_FAIL;
	}
    */
	/* check if we should enable Permanent DEP mitigation */
	if ( MCEDP_REGCONFIG.GENERAL.PERMANENT_DEP )
	{
		if ( EnablePermanentDep() != MCEDP_STATUS_SUCCESS )
		{
			REPORT_ERROR("EnablePermanentDep()", &err);
			return MCEDP_STATUS_GENERAL_FAIL;
		}
	}

	/* check if we should enable NULL Page Allocation Prevention mitigation  */
	if ( MCEDP_REGCONFIG.GENERAL.NULL_PAGE )
	{
		if ( EnableNullPageProtection() != MCEDP_STATUS_SUCCESS )
		{
			REPORT_ERROR("EnableNullPageProtection()", &err);
			return MCEDP_STATUS_GENERAL_FAIL;
		}
	}

	/* check if we should enable Heap Spray Prevention mitigation  */
	if ( MCEDP_REGCONFIG.GENERAL.HEAP_SPRAY )
	{
		if ( EnableHeapSprayProtection(MCEDP_REGCONFIG.GENERAL.HEAP_SPRAY_ADDRESS) != MCEDP_STATUS_SUCCESS )
		{
			REPORT_ERROR("EnableNullPageProtection()", &err);
			return MCEDP_STATUS_GENERAL_FAIL;
		}
	}

	/* if Export Table Access Vaidation is enable then activate it! */
	if ( MCEDP_REGCONFIG.SHELLCODE.ETA_VALIDATION )
	{
		/* add exception handler for handling break points */
		if ( !AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)DbgExceptionHandler) )
		{
			REPORT_ERROR("AddVectoredExceptionHandler()", &err);
			return MCEDP_STATUS_INTERNAL_ERROR;
		}
		
		/* log current loaded modules */
		if ( LdrLoadListEntry() != MCEDP_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "ListProcessModules() faild!\n");
			return MCEDP_STATUS_GENERAL_FAIL;
		}

		/* enable ETA validation for all current running threads */
		if ( DbgEnableExportAddressFiltering() != MCEDP_STATUS_SUCCESS)
		{
			DEBUG_PRINTF(LDBG, NULL, "Error occured in DbgEnableExportAddressFiltering()");
			if ( !MCEDP_REGCONFIG.SKIP_HBP_ERROR )
				return MCEDP_STATUS_GENERAL_FAIL;
		}
	}

	/* hook functions! */
	if ( HookInstall() != MCEDP_STATUS_SUCCESS )
	{
		DEBUG_PRINTF(LDBG, NULL, "Error in Hooking process!\n");
		return MCEDP_STATUS_GENERAL_FAIL;
	}

	DEBUG_PRINTF(LDBG, NULL, "Functions hooked successfully!\n");
	return MCEDP_STATUS_SUCCESS;
}