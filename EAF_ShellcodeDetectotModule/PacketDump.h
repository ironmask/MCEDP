#include <stdio.h>
#define HAVE_REMOTE
#include "winpcap\Include\pcap.h"
#include <Windows.h>
#include "LogInfo.h"
#include "ParsConfig.h"
#pragma comment(lib,"winpcap\\Lib\\Packet.lib")
#pragma comment(lib,"winpcap\\Lib\\wpcap.lib")
#pragma once

extern MCEDPREGCONFIG MCEDP_REGCONFIG;

VOID 
PacketDumperCallback(
	IN UCHAR *szDumpFileFullPath, 
	IN CONST struct pcap_pkthdr *PacketHeader, 
	IN CONST UCHAR *PacketData
	);

STATUS
DumpNetworkActivity(
	VOID
	);
