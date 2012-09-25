#include "ShellcodeUtils.h"

STATUS
ShuDumpShellcode(
	IN PVOID Address
	)
{
	LPVOID	lpStartAddress;
	LPVOID	lpEndAddress;
	CHAR szLogPath[MAX_PATH];
	CHAR szShellcodeFile[MAX_PATH];
	BYTE *ShellcodeDump;
	DWORD dwRead;
	DWORD dwWrite;
	ERRORINFO err;
	HANDLE hShellcodeFile;
	STATUS status;

	lpStartAddress	= Address;
	lpEndAddress	= Address;
	ShellcodeDump	= (BYTE *)LocalAlloc(LMEM_ZEROINIT, 2048);

	/* IsBadReadPtr sucks so I have to validate memory readability by ReadProcessMemory */
	while ( ReadProcessMemory( GetCurrentProcess(), 
                               (LPVOID)((DWORD)lpStartAddress - 4),
		                       ShellcodeDump,
		                       4,
		                       &dwRead) 
		    && ((DWORD)Address - (DWORD)lpStartAddress) < 0x200 )
	{
		lpStartAddress = (LPVOID)((DWORD)lpStartAddress - 4);
	}

	while ( ReadProcessMemory( GetCurrentProcess(),
		                       (LPVOID)((DWORD)lpEndAddress + 4),
			                   ShellcodeDump,
			                   4,
			                   &dwRead) 
			&& ((DWORD)lpEndAddress - (DWORD)Address) < 0x200)
	{
		lpEndAddress = (LPVOID)((DWORD)lpEndAddress + 4);
	}

	sprintf(szShellcodeFile, "\\Shellcode.bin");
	strncpy( szLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH);
	strncat(szLogPath, szShellcodeFile, MAX_PATH);

    /* Dump shellcode from memory */
	ReadProcessMemory( GetCurrentProcess(),
		               lpStartAddress,
					   ShellcodeDump,
					   ((DWORD)lpEndAddress - (DWORD)lpStartAddress),
					   &dwRead);

	if ( dwRead != ((DWORD)lpEndAddress - (DWORD)lpStartAddress) )
	{
		REPORT_ERROR("ReadProcessMemory()", &err);
		LocalFree(ShellcodeDump);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	hShellcodeFile = CreateFile( szLogPath,
		                         GENERIC_WRITE,
								 0,
								 NULL,
								 CREATE_ALWAYS,
								 FILE_ATTRIBUTE_NORMAL,
								 NULL);

	if ( hShellcodeFile == INVALID_HANDLE_VALUE )
	{
		REPORT_ERROR("CreateFile()", &err);
		LocalFree(ShellcodeDump);
		return MCEDP_STATUS_INTERNAL_ERROR;	
	}

	WriteFile( hShellcodeFile, 
		       ShellcodeDump,
			   dwRead,
			   &dwWrite,
			   NULL);

	if ( dwRead != dwWrite )
	{
		REPORT_ERROR("WriteFile()", &err);
		LocalFree(ShellcodeDump);
		CloseHandle(hShellcodeFile);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	DEBUG_PRINTF(LDBG, NULL, "Shellcode Dumped from (0x%p -- 0x%p) Size ( 0x%p )\n", lpStartAddress, lpEndAddress, ((DWORD)lpEndAddress - (DWORD)lpStartAddress));

    /* log and dump disassembled version of in-memory shelloce */
	status = ShuDisassembleShellcode( lpStartAddress, lpStartAddress, ((DWORD)lpEndAddress - (DWORD)lpStartAddress));
	if ( status == MCEDP_STATUS_SUCCESS )
		DEBUG_PRINTF(LDBG, NULL, "Shellcode disassembled successfully!\n");
	else if ( status == MCEDP_STATUS_PARTIAL_DISASSEMBLE )
		DEBUG_PRINTF(LDBG, NULL, "Only a part of Shellcode disassembled successfully!\n");
	else
		DEBUG_PRINTF(LDBG, NULL, "Faild to disassemble Shellcode!\n");

	LocalFree(ShellcodeDump);
	CloseHandle(hShellcodeFile);
	return MCEDP_STATUS_SUCCESS;
}

STATUS
ShuDisassembleShellcode(
	IN PVOID DumpedShellcode,
	IN PVOID ShellcodeAddress,
	IN DWORD dwSize
	)
{
	_DecodeResult DecRes;
	_DecodedInst *DecodedInstructions;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset;
	DWORD dwDecodedInstructionsCount;
	DWORD dwNext;
	DWORD i;
	CHAR szLogPath[MAX_PATH];
	CHAR szShellcodeDisassFile[MAX_PATH];
	ERRORINFO err;
	FILE *ShellcodeFile;

	offset = 0;
	dwDecodedInstructionsCount = 0;
	DecodedInstructions = (_DecodedInst *)LocalAlloc(LMEM_ZEROINIT, MAX_INSTRUCTIONS * sizeof(_DecodedInst));

	sprintf(szShellcodeDisassFile, "\\ShellcodeDisass.txt");
	strncpy( szLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH);
	strncat(szLogPath, szShellcodeDisassFile, MAX_PATH);
	
	ShellcodeFile = fopen( szLogPath, "a");

	if ( ShellcodeFile == NULL )
	{
		REPORT_ERROR("fopen()", &err);
		LocalFree(DecodedInstructions);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	while ( TRUE ) 
	{
		DecRes = distorm_decode(offset, (const unsigned char*)DumpedShellcode, dwSize, dt, DecodedInstructions, MAX_INSTRUCTIONS, (unsigned int *)&dwDecodedInstructionsCount);
		if (DecRes == DECRES_INPUTERR)
			return MCEDP_STATUS_GENERAL_FAIL;

		for ( i = 0; i < dwDecodedInstructionsCount; i++ ) 
			fprintf(ShellcodeFile, "%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, DecodedInstructions[i].offset + (DWORD)ShellcodeAddress, DecodedInstructions[i].size, (char*)DecodedInstructions[i].instructionHex.p, (char*)DecodedInstructions[i].mnemonic.p, DecodedInstructions[i].operands.length != 0 ? " " : "", (char*)DecodedInstructions[i].operands.p);

		if ( DecRes == DECRES_SUCCESS || dwDecodedInstructionsCount == 0 ) 
			break;

		dwNext = (unsigned long)(DecodedInstructions[dwDecodedInstructionsCount-1].offset - offset);
		dwNext += DecodedInstructions[dwDecodedInstructionsCount-1].size;
		DumpedShellcode =  (PVOID)((unsigned int)DumpedShellcode + dwNext);
		dwSize -= dwNext;
		offset += dwNext;
	}

	LocalFree(DecodedInstructions);
	fclose(ShellcodeFile);
	return MCEDP_STATUS_SUCCESS;
}

STATUS
ShuDisassmbleRopInstructions(
	IN PVOID Address,
	OUT PCHAR szInstruction,
	IN DWORD dwSize
	)
{
	_DecodeResult DecRes;
	_DecodedInst *DecodedInstructions;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset;
	CHAR szDecodedInst[1024];
	DWORD dwDecodedInstructionsCount;
	DWORD dwNext;
	DWORD i;

	offset = 0;
	dwDecodedInstructionsCount = 0;
	DecodedInstructions = (_DecodedInst *)LocalAlloc(LMEM_ZEROINIT, MAX_INSTRUCTIONS * sizeof(_DecodedInst));

	while ( TRUE ) 
	{
		
		DecRes = distorm_decode(offset, (const unsigned char*)Address, dwSize, dt, DecodedInstructions, MAX_INSTRUCTIONS, (unsigned int *)&dwDecodedInstructionsCount);
		if (DecRes == DECRES_INPUTERR)
			return MCEDP_STATUS_GENERAL_FAIL;

		for ( i = 0; i < dwDecodedInstructionsCount; i++ ) {

			SecureZeroMemory(szDecodedInst, 1024);
			sprintf(szDecodedInst, "%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, DecodedInstructions[i].offset + (DWORD)Address, DecodedInstructions[i].size, (char*)DecodedInstructions[i].instructionHex.p, (char*)DecodedInstructions[i].mnemonic.p, DecodedInstructions[i].operands.length != 0 ? " " : "", (char*)DecodedInstructions[i].operands.p);
			strcat( szInstruction , szDecodedInst);

			/* Using Decompose API with DF_STOP_ON_RET ? */
			if ( strstr((char*)DecodedInstructions[i].mnemonic.p, "RET") != NULL ||
				 strstr((char*)DecodedInstructions[i].operands.p, "RET") != NULL )
			{
				LocalFree(DecodedInstructions);
				return MCEDP_STATUS_SUCCESS;
			}
		}

		if ( DecRes == DECRES_SUCCESS || dwDecodedInstructionsCount == 0 ) 
			break;

		dwNext = (unsigned long)(DecodedInstructions[dwDecodedInstructionsCount-1].offset - offset);
		dwNext += DecodedInstructions[dwDecodedInstructionsCount-1].size;
		Address =  (PVOID)((unsigned int)Address + dwNext);
		dwSize -= dwNext;
		offset += dwNext;
	}

	LocalFree(DecodedInstructions);
	return MCEDP_STATUS_SUCCESS;
}
