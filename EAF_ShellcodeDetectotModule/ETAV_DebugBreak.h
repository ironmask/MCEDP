#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <time.h>
#include <UrlMon.h>
#include "LogInfo.h"
#include "ShellcodeUtils.h"
#include "PEUtils.h"
#include "ParsConfig.h"

#define HW_ACCESS_STR				"HW_ON_ACCESS"
#define HW_EXECUTE_STR				"HW_ON_EXECUTE"
#define HW_WRITE_STR				"HW_ON_WRITE"
#define HW_ACCESS					0x00000003
#define HW_EXECUTE					0x00000000
#define HW_WRITE					0x00000001
#define DR_ALL_BUSY					0x00000004
#define DR_BREAK_SET				0x00000007
#define DR_BREAK_ERROR_UNK			0x00000013
#define	THREAD_ALREADY_SUSPEND		0x00000010

extern MCEDPREGCONFIG MCEDP_REGCONFIG;

typedef struct _HWBREAKDATA
{
	PVOID	Address;
	DWORD	dwCondition;
	DWORD	dwSize;
	DWORD	dwThreadId;
	DWORD	dwStatus;
	DWORD	dwThreadStatus;
	DWORD	dwDrBusyRemove;
} HWBREAKDATA, *PHWBREAKDATA;

LONG 
CALLBACK 
DbgExceptionHandler(
	PEXCEPTION_POINTERS ExceptionInfo
	);

STATUS 
DbgThreadSetBreakpoint(
	IN PHWBREAKDATA BreakpointData
	);

STATUS 
DbgThreadUnSetBreakpoint(
	IN PDWORD pdwThreadId
	);

STATUS
DbgEnableExportAddressFiltering(
	VOID
	);

STATUS
DbgDisableExportAddressFiltering(
	VOID
	);

STATUS
DbgValidateExportTableAccess(
	IN PVOID Address,
	OUT PCHAR szModuleName
	);

STATUS
DbgSetShellcodeFlag(
	VOID
	);

STATUS
DbgGetShellcodeFlag(
	VOID
	);