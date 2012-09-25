#include "geoip\GeoIP.h"
#include "LogInfo.h"
#include "ParsConfig.h"

#define MAX_COUNTRY_NAME_SIZE 100
typedef GeoIP GEOIP;
typedef GeoIP* PGEOIP;
extern EAFCONFIG EAF_CONFIG;

STATUS
GetIpOrigin(
	IN CONST PCHAR Ip,
	OUT PCHAR Country,
	IN CONST DWORD Size
	);