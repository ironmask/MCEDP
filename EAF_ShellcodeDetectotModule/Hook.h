#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <time.h>
#include <UrlMon.h>
#include "LogInfo.h"
#include "ETAV_DebugBreak.h"
#include "ModuleAutoInject.h"
#include "XmlLog.h"
#include "RopDetection.h"
#include "detours\detours.h"
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"detours\\detours_nodll.lib")

static    BOOL (WINAPI *CreateProcessInternalW_ )(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken);
static  HANDLE (WINAPI *CreateThread_           )(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = CreateThread;
static HRESULT (WINAPI *URLDownloadToFileW_     )(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB ) = URLDownloadToFileW;
static HRESULT (WINAPI *URLDownloadToFileA_     )(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB ) = URLDownloadToFileA;
static HMODULE (WINAPI *LoadLibraryExW_         )( LPCWSTR lpLibFileName,  HANDLE hFile,  DWORD dwFlags) = LoadLibraryExW;
static  SOCKET (WSAAPI *socket_                 )( int af, int type, int protocol ) = socket;
static  SOCKET (WSAAPI *accept_                 )( SOCKET s, struct sockaddr *addr, int *addrlen ) = accept;
static     int (WSAAPI *connect_                )( SOCKET s, const struct sockaddr *name, int namelen ) = connect;
static     int (WSAAPI *listen_                 )( SOCKET s, int backlog ) = listen;
static     int (WSAAPI *bind_                   )( SOCKET s, const struct sockaddr *name, int namelen ) = bind;
static     int (WSAAPI *send_                   )( SOCKET s, const char *buf, int len, int flags ) = send;
static     int (WSAAPI *recv_                   )( SOCKET s, char *buf, int len, int flags ) = recv;

extern MCEDPREGCONFIG MCEDP_REGCONFIG;
extern DWORD dwEaAccessCount;
extern BOOL bShellcodeDetected;
extern PXMLNODE XmlLog;
extern PXMLNODE XmlShellcode;

#define INIT_WAIT_TIME 2000

STATUS
HookInstall(
	VOID
	);

STATUS
HookUninstall(
	VOID
	);

HANDLE 
WINAPI 
HookedCreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes, 
	SIZE_T dwStackSize, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	LPVOID lpParameter, 
	DWORD dwCreationFlags, 
	LPDWORD lpThreadId
	);

BOOL
WINAPI
HookedCreateProcessInternalW(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
	);

HRESULT
WINAPI
HookedURLDownloadToFileA(
    LPUNKNOWN pCaller,
    LPCTSTR szURL,
    LPCTSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
	);

HRESULT
WINAPI
HookedURLDownloadToFileW(
    LPUNKNOWN pCaller,
    LPCWSTR szURL,
    LPCWSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
	);

HMODULE 
WINAPI
HookedLoadLibraryExW(
	LPCWSTR lpLibFileName, 
	HANDLE hFile, 
	DWORD dwFlags
	);

extern "C"
LPVOID
WINAPI 
HookedMapViewOfFileEx(
	HANDLE hFileMappingObject, 
	DWORD dwDesiredAccess, 
	DWORD dwFileOffsetHigh, 
	DWORD dwFileOffsetLow, 
	SIZE_T dwNumberOfBytesToMap,
	LPVOID lpBaseAddress
	);

extern "C"
LPVOID
WINAPI 
HookedMapViewOfFile(
	HANDLE hFileMappingObject, 
	DWORD dwDesiredAccess, 
	DWORD dwFileOffsetHigh, 
	DWORD dwFileOffsetLow, 
	SIZE_T dwNumberOfBytesToMap
	);

extern "C"
BOOL
WINAPI
HookedVirtualProtectEx(
	HANDLE hProcess, 
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	PDWORD flProtect
	);

extern "C"
BOOL
WINAPI
HookedVirtualProtect(
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	PDWORD flProtect
	);

extern "C"
LPVOID
WINAPI
HookedVirtualAllocEx(
	HANDLE hProcess, 
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	DWORD flProtect
	);

extern "C"
LPVOID
WINAPI 
HookedVirtualAlloc(
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	DWORD flProtect
	);

extern "C"
HANDLE
WINAPI 
HookedHeapCreate(
	DWORD flOptions,
	SIZE_T dwInitialSize,
	SIZE_T dwMaximumSize
);

SOCKET
WSAAPI
Hookedsocket(
	int af,
	int type,
	int protocol
	);

int
WSAAPI
Hookedconnect(
	SOCKET s,
    const struct sockaddr *name,
	int namelen
    );

int
WSAAPI
Hookedlisten(
	SOCKET s,
	int backlog
	);

int
WSAAPI
Hookedbind(
  SOCKET s,
  const struct sockaddr *name,
  int namelen
  );

SOCKET
WSAAPI
Hookedaccept(
	SOCKET s,
	struct sockaddr *addr,
	int *addrlen
	);


int
WSAAPI
Hookedsend(
	SOCKET s,
	const char *buf,
	int len,
	int flags
	);

int
WSAAPI
Hookedrecv(
	SOCKET s,
	char *buf,
	int len,
	int flags
	);
