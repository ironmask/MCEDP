#include "LogInfo.h"
#include "ParsConfig.h"
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#pragma once

//#define HONEYCLIENT

#define SHARED_MEM_PERFIX		"OPSH_"
#define MAX_OP_PID				10
#define PROCESS_TIME			4

#define IPC_APP_TYPE			0x80000000
#define IPC_APP_PATH			0x40000000
#define IPC_OP_DIR				0x20000000
#define IPC_STATUS				0x10000000
#define IPC_START_TIME			0x8000000
#define IPC_OP_PID				0x4000000
#define IPC_OUTPUT_DIR			0x2000000
#define IsBitSet(val, bit) ((val) & (1 << (bit)))

extern HMODULE hGlobalDllHandle;

typedef NTSTATUS ( __stdcall *NtQueryInformationProcess_)( 
	IN HANDLE ProcessHandle,
	IN ULONG ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef struct _KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES;
typedef KERNEL_USER_TIMES *PKERNEL_USER_TIMES;

typedef struct _OPPID
{
	DWORD dwPID;
	LARGE_INTEGER CreateTime;
} OPPID, *POPPID;

typedef struct _OPDTA
{
	LARGE_INTEGER StartTime;			// unused
	CHAR szAppType[MAX_CONFIG_STR];		// unused
	CHAR szAppPath[MAX_PATH];			// unused
	CHAR szOPDir[MAX_PATH];				// 
	CHAR szOutputDir[MAX_PATH];			// path or url hash value
	OPPID OperationPID[MAX_OP_PID];		// operation pids
	DWORD dwStatus;						// set to proper value
} OPDATA, *POPDATA;

STATUS
GetCurrentOperationDir(
	OUT PCHAR szOpDir,
	IN DWORD dwSize
	);

STATUS
SetOperationData(
	IN PCHAR szDirectory,
	IN POPDATA pOperationData,
	IN DWORD dwFlags
	);

STATUS
GetProcessCreateTime( 
	IN HANDLE hProcess,
	OUT PLARGE_INTEGER CreateTime
	);

STATUS
GetOperationData(
	IN CHAR* szDirectory,
	IN POPDATA pOperationData
	);