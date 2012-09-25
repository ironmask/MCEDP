#include "MalGeoIp.h"

STATUS
GetIpOrigin(
	IN CONST PCHAR Ip,
	OUT PCHAR Country,
	IN CONST DWORD Size
	)
{
	PGEOIP gi;
	CHAR szDbPath[MAX_PATH];
	DWORD dwCountryId;

	GetLogPath( szDbPath, MAX_PATH );
	strncat( szDbPath, "\\", MAX_PATH);
	strncat( szDbPath, EAF_CONFIG.EA_GEOIP_DB_STR , MAX_PATH);
	GeoIP_setup_custom_directory(szDbPath);

	gi = GeoIP_new(GEOIP_STANDARD);
	MessageBox(NULL, "1", NULL, MB_OK);
	MessageBox(NULL, szDbPath, NULL, MB_OK);

	dwCountryId = GeoIP_id_by_name(gi, Ip);

	MessageBox(NULL, "2", NULL, MB_OK);

	if ( Size < MAX_COUNTRY_NAME_SIZE )
		return EAF_STATUS_GENERAL_FAIL;

	MessageBox(NULL, "3", NULL, MB_OK);
	MessageBox(NULL, GeoIP_country_name_by_id(gi, dwCountryId), NULL, MB_OK);
	strncpy( Country, GeoIP_country_name_by_id(gi, dwCountryId), MAX_COUNTRY_NAME_SIZE);
	MessageBox(NULL, "4", NULL, MB_OK);
	return EAF_STATUS_SUCCESS;
}