#include "GeneralProtections.h"

STATUS
EnablePermanentDep(
	VOID
	)
{
	NTSTATUS Status;
	ULONG ExecuteFlags;
	NtSetInformationProcess_ NtSetInformationProcess;

	NtSetInformationProcess = (NtSetInformationProcess_)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtSetInformationProcess"));
	if ( NtSetInformationProcess != NULL )
	{
        /* Set up proper flags, call NtSetInformationProcess to disble RW memory execution and make it permanent */
		ExecuteFlags = MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_PERMANENT;
		Status = NtSetInformationProcess( GetCurrentProcess(),
										  ProcessExecuteFlags,
										  &ExecuteFlags,
										  sizeof(ExecuteFlags));
		if ( NT_SUCCESS(Status) )
		{
			DEBUG_PRINTF(LDBG, NULL, "Permanent DEP Enabled!\n");
			return MCEDP_STATUS_SUCCESS;
		}
	}

	return MCEDP_STATUS_INTERNAL_ERROR;
}

STATUS
EnableNullPageProtection(
	VOID
	)
{
	NTSTATUS Status;
	SIZE_T RegionSize;
	LPVOID lpBaseAddress;
	NtAllocateVirtualMemory_ NtAllocateVirtualMemory;

	NtAllocateVirtualMemory = (NtAllocateVirtualMemory_)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtAllocateVirtualMemory"));
	if ( NtAllocateVirtualMemory != NULL )
	{
        /* Allocate null page and first 0x1000 bytes proceeding it */
		RegionSize = 0x1000;
		lpBaseAddress= (PVOID)0x1;
		Status = NtAllocateVirtualMemory( GetCurrentProcess(), 
			                              &lpBaseAddress, 
										  0L, 
										  &RegionSize, 
										  MEM_COMMIT | MEM_RESERVE, 
										  PAGE_NOACCESS);
		if ( NT_SUCCESS(Status) )
		{
			DEBUG_PRINTF(LDBG, NULL, "NULL Page Allocation Prevention Enabled!\n");
			return MCEDP_STATUS_SUCCESS;
		}
	}

	return MCEDP_STATUS_INTERNAL_ERROR;
}

STATUS
EnableHeapSprayProtection(
	IN PCHAR szHeapAddressArray
	)
{
	PCHAR szHeapAddress;
	DWORD dwHeapAddress;

	szHeapAddress = strtok (szHeapAddressArray,";");
	while (szHeapAddress != NULL)
	{
        /* Preallocate common Heap Spray address */
		dwHeapAddress = strtol(szHeapAddress, NULL, 0);
		VirtualAlloc((LPVOID)dwHeapAddress, 0x400, MEM_RESERVE, PAGE_NOACCESS);
		szHeapAddress = strtok (NULL,";");
	}

	return MCEDP_STATUS_SUCCESS;
}