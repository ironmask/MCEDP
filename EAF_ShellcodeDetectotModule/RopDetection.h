#include <Windows.h>
#include <stdlib.h>
#include "ParsConfig.h"
#include "LdrList.h"
#include "XmlLog.h"
#include "LogInfo.h"
#include "ETAV_DebugBreak.h"
#pragma once

extern MCEDPREGCONFIG MCEDP_REGCONFIG;
extern PXMLNODE XmlLog;
extern PXMLNODE XmlShellcode;

typedef enum _ROP_CALLEE { 
	CalleeVirtualAlloc          = 0,
	CalleeVirtualAllocEx        = 1,
	CalleeVirtualProtect        = 2,
	CalleeVirtualProtectEx      = 3,
	CalleeMapViewOfFile         = 4,
	CalleeMapViewOfFileEx		= 5,
	CalleeHeapCreate			= 6,
	CalleeWriteProcessMemory	= 7,
} ROP_CALLEE;

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect
	);

STATUS
DbgGetRopModule(
	IN PVOID StackPointerAddress,
	OUT PCHAR ModuleFullName,
	IN DWORD dwSize
	);

STATUS
DbgSetRopFlag(
	VOID
	);

STATUS
DbgGetRopFlag(
	VOID
	);

VOID
DbgReportRop(
	IN CONST PVOID Address,
	IN CONST DWORD APINumber
	);