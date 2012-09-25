#include <Windows.h>
#include "LogInfo.h"
#pragma once

STATUS
InjectDLLIntoProcess(
	IN PCHAR szDllPath,
	IN HANDLE hProcessHandle
	);