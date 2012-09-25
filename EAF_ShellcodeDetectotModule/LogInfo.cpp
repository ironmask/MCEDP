#include "LogInfo.h"
#include "ParsConfig.h"

extern MCEDPREGCONFIG MCEDP_REGCONFIG;
BOOL bLogStart = FALSE;
BOOL bLogPathInitSuccess = FALSE;


VOID 
REPORT_ERROR( 
	IN PCHAR Function,
	OUT PERRORINFO ErrorInfo
	)
{
	ErrorInfo->dwErrorNum = GetLastError();
    REPORT_ERROR_EX( Function,
		             GetLastError(),
				     ErrorInfo);
}

VOID 
REPORT_ERROR_EX(
	IN PCHAR Function,
	IN DWORD dwErrorNumber,
	OUT PERRORINFO ErrorInfo
	)
{
	BOOL bErrorHandle;
	HMODULE hErrorDllHandle;

	if ( TRUE ) /* Check for EAF_CONFIG.DISABLE_LOGGING */
	{
		ErrorInfo->dwErrorNum = dwErrorNumber;
		bErrorHandle = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
									  NULL,
									  ErrorInfo->dwErrorNum,
									  MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
									  ErrorInfo->ErrorMsg,
									  256,
									  NULL);
		if ( bErrorHandle == FALSE )
		{
			/* load library and check the error again for network related errors */
			hErrorDllHandle = LoadLibraryEx("netmsg.dll",
											 NULL,
											 DONT_RESOLVE_DLL_REFERENCES);
			if ( hErrorDllHandle != NULL )
			{
				bErrorHandle = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
											  NULL,
											  ErrorInfo->dwErrorNum,
											  MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
											  ErrorInfo->ErrorMsg,
											  256,
											  NULL);
			}
		}
		if ( bErrorHandle == FALSE )
		{
			strncpy(ErrorInfo->ErrorMsg,"Unknown Error", 256);
		}

		/* allocate memory for completed error message */
		ErrorInfo->CompletErrorMsg = (CHAR *) LocalAlloc( LMEM_ZEROINIT, 512 );
        _snprintf( ErrorInfo->CompletErrorMsg , MAX_ERROR_MSG, "[!] ERROR : %s failed with error %d (%s)\n", Function, ErrorInfo->dwErrorNum, ErrorInfo->ErrorMsg );
		DEBUG_PRINTF(LDBG, NULL, "%s",ErrorInfo->CompletErrorMsg);
        /* This should free by caller */
        LocalFree(ErrorInfo->CompletErrorMsg);
	}
}

VOID 
DEBUG_PRINTF(
	IN DWORD dwType,
	IN DWORD dwTID,
	IN PCHAR Format, 
	IN ...
	)
{
    CHAR Buffer[1024] = {0};
	CHAR szFullLogPath[MAX_PATH];
	FILE *fp;
    va_list Args;

	va_start(Args, Format);
	vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
	va_end(Args);

	strncpy( szFullLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH );
#ifdef __DEBUG__
	if ( dwType == LDBG )
    {
        strncpy( szFullLogPath, MCEDP_REGCONFIG.DBG_LOG_PATH, MAX_PATH );
        strncat( szFullLogPath, "\\LogInfo.txt", MAX_PATH);
    }
#else
    if ( dwType == LDBG )
        return;
#endif
	else if ( dwType == LSHL )
        strncat(szFullLogPath, "\\ShellcodeAnalysis.txt", MAX_PATH);
	else if ( dwType == LROP )
        strncat(szFullLogPath, "\\RopAnalysis.txt", MAX_PATH);

	fflush(stdout);
	fflush(stderr);

	fp = fopen(szFullLogPath, "a");
	if ( fp == NULL )
		return;

    if ( !bLogStart )
    {
        fprintf(fp, "\n=========================================================================================\n");
        bLogStart = TRUE;
    }
    
	fprintf(fp, "%s", Buffer);
	fflush(fp);
	fclose(fp);
	return;
}

STATUS
InitLogPath(
	OUT PCHAR LogPath,
	IN DWORD Size
	)
{
	CHAR szLogPath[MAX_PATH];
	SYSTEMTIME lt;

    if ( bLogPathInitSuccess )
        return MCEDP_STATUS_SUCCESS;

	SecureZeroMemory(szLogPath, MAX_PATH);
	GetLocalTime( &lt);
	/* init log path by time stamp */
	_snprintf( szLogPath, MAX_PATH, "\\%s\\%d.%d.%d ,%d-%d-%d-%d", MCEDP_REGCONFIG.APP_PATH_HASH, lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
	strncat( LogPath,  szLogPath ,Size );

	if ( FolderExists( LogPath ) )
    {
        bLogPathInitSuccess = TRUE;
		return MCEDP_STATUS_SUCCESS;
    }

	if ( CreateDirectory( LogPath, NULL ) )
    {
        bLogPathInitSuccess = TRUE;
		return MCEDP_STATUS_SUCCESS;
    }

	return MCEDP_STATUS_INTERNAL_ERROR;	
}

BOOL 
FolderExists(
	LPTSTR szFolderName
	)
{   
    return (GetFileAttributes(szFolderName) != INVALID_FILE_ATTRIBUTES) ? TRUE : FALSE;   
}

PCHAR
strtolow(
    PCHAR szString
    )
{
    PCHAR Container;
    Container = szString;

	while(*Container) 
    {
        *Container = tolower(*Container);
		Container++;
	}

	return szString;
}

VOID
HexDumpToFile(
    PBYTE Data, 
    DWORD dwSize, 
    PCHAR szFileName
    ) 
{
   UINT dp, p;
   FILE *fp;
   CHAR szFullLogPath[MAX_PATH];
   CONST CHAR trans[] = "................................ !\"#$%&'()*+,-./0123456789"
                        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
                        "nopqrstuvwxyz{|}~...................................."
                        "....................................................."
                        "........................................";
    
   strncpy( szFullLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH );
   strncat(szFullLogPath, "\\", MAX_PATH);
   strncat(szFullLogPath, szFileName, MAX_PATH);
   strncat(szFullLogPath, ".txt", MAX_PATH);

	fp = fopen(szFullLogPath, "a");
	if ( fp == NULL )
		return; 

    for (dp = 1; dp <= dwSize; dp++)  
    {
        fprintf(fp,"%02x ", Data[dp-1]);
        if ((dp % 8) == 0)
            fprintf(fp," ");
        if ((dp % 16) == 0) 
        {
            fprintf(fp,"| ");
            p = dp;
            for (dp -= 16; dp < p; dp++)
                fprintf(fp,"%c", trans[Data[dp]]);
            fprintf(fp,"\n");
        }
    }

    if ((dwSize % 16) != 0)
    {
        p = dp = 16 - (dwSize % 16);
        for (dp = p; dp > 0; dp--) 
        {
            fprintf(fp,"   ");
            if (((dp % 8) == 0) && (p != 8))
                fprintf(fp," ");
        }
        fprintf(fp," | ");
        for (dp = (dwSize - (16 - p)); dp < dwSize; dp++)
            fprintf(fp,"%c", trans[Data[dp]]);
    }
    fprintf(fp,"\n");
    fflush(fp);
    fclose(fp);
    return;
}


PCHAR
GenRandomStr(
    PCHAR szString, 
    DWORD dwSize
    ) 
{
    DWORD dwSeed;
    CONST CHAR alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";

    Sleep(100);
    dwSeed = ((DWORD)&dwSeed >> 8) ^ (GetTickCount() >> 8) ^ GetCurrentThreadId();
    srand(dwSeed);

    for (int i = 0; i < dwSize; ++i)
        szString[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

    szString[dwSize] = 0;
    return szString;
}