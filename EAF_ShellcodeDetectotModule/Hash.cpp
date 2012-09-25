#include "Hash.h"

STATUS
GetSHA1Hash(
	IN CONST PBYTE Buffer,
    IN CONST DWORD BufferSize,
    OUT PBYTE HashValue,
	IN OUT PDWORD HashValueSize
	)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD dwHashSize;
	DWORD dwCount;
	BOOL bCryptResult;
	ERRORINFO err;

	dwCount = sizeof(DWORD);

	bCryptResult = CryptAcquireContext( &hProv, 
		                                NULL, 
							            NULL, 
							            PROV_RSA_FULL, 
							            CRYPT_VERIFYCONTEXT);
	if ( bCryptResult == FALSE )
	{
		REPORT_ERROR("CryptAcquireContext", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	bCryptResult = CryptCreateHash( hProv, 
		                            CALG_SHA1, 
									0, 
									0, 
									&hHash);
	if ( bCryptResult == FALSE)
	{
		REPORT_ERROR("CryptCreateHash", &err);
		CryptDestroyHash(hHash);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	bCryptResult = CryptHashData(hHash, (CONST PBYTE) Buffer, BufferSize, 0);

	if ( bCryptResult == FALSE )
	{
		REPORT_ERROR("CryptHashData", &err);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	bCryptResult = CryptGetHashParam( hHash, 
		                              HP_HASHSIZE, 
									  (PBYTE)&dwHashSize, 
									  &dwCount, 
									  0);

	if ( *HashValueSize < dwHashSize )
	{
		DEBUG_PRINTF( LDBG, NULL, "Hash Buffer too small\n");
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return MCEDP_STATUS_INSUFFICIENT_BUFFER;
	}

	bCryptResult = CryptGetHashParam( hHash, 
		                              HP_HASHVAL, 
									  HashValue, 
									  HashValueSize, 
									  0);

	if ( bCryptResult == FALSE )
	{
		REPORT_ERROR("CryptGetHashParam", &err);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

	*HashValueSize = dwHashSize;
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	return MCEDP_STATUS_SUCCESS;
} 


PCHAR
HashToStr(
	IN PBYTE Hash,
	IN DWORD dwHashSize,
	IN PCHAR szHash,
	IN DWORD dwHashStrSize
	)
{

	CHAR szTemp[5];
	DWORD i;
	SecureZeroMemory( szHash, dwHashStrSize );

	for ( i = 0; i < dwHashSize; i++ )
	{
		SecureZeroMemory( szTemp, 5 );
		sprintf(szTemp, "%.2X", Hash[i]);
		strncat(szHash, szTemp, dwHashStrSize);
	}

	return szHash;
}

