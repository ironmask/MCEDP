#include <Windows.h>
#include <stdlib.h>
#include "LogInfo.h"
#define MAX_HASH_SIZE 256

STATUS
GetSHA1Hash(
	IN CONST PBYTE Buffer,
    IN CONST DWORD BufferSize,
    OUT PBYTE HashValue,
	IN OUT PDWORD HashValueSize
	);


PCHAR
HashToStr(
	IN PBYTE Hash,
	IN DWORD dwHashSize,
	IN PCHAR szHash,
	IN DWORD dwHashStrSize
	);