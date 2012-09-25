#include "PacketDump.h"


VOID 
PacketDumperCallback(
	IN UCHAR *szDumpFileFullPath, 
	IN CONST struct pcap_pkthdr *PacketHeader, 
	IN CONST UCHAR *PacketData
	)
{
    pcap_dump(szDumpFileFullPath, PacketHeader, PacketData);
}

STATUS
DumpNetworkActivity(
	VOID
	)
{
	CHAR szPacketFileName[MAX_PATH];
	CHAR szPacketFilePath[MAX_PATH];
	CHAR ErrorInfo[PCAP_ERRBUF_SIZE];
	pcap_if_t *DeviceList;
	pcap_if_t *DeviceListIterator;
	pcap_t *DeviceHandle;
	pcap_dumper_t *DumpFile;
	DWORD i = 0;
    

	SHGetFolderPath(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, szPacketFilePath);
	sprintf(szPacketFileName, "\\%s-%d.pcap", EAF_CONFIG.PACKET_DUMP_FILE, EAF_CONFIG.LOG_ID);
	strncat( szPacketFilePath, szPacketFileName, MAX_PATH);

	DEBUG_PRINTF(LDBG, NULL, "Packet Capturing Info: \n");

    // Retrieve the device list on the local machine
    if ( pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &DeviceList, ErrorInfo) == -1 )
    {
		DEBUG_PRINTF(LDBG, NULL, "pcap_findalldevs() faild : %s\n", ErrorInfo);
		return MCEDP_STATUS_INTERNAL_ERROR;
    }
    
    for( DeviceListIterator = DeviceList; DeviceListIterator ; DeviceListIterator = DeviceListIterator->next )
    {
        DEBUG_PRINTF(LDBG, NULL, "%d. %s", ++i, DeviceListIterator->name);
        if ( DeviceListIterator->description )
            DEBUG_PRINTF(LDBG, NULL, " (%s).\n", DeviceListIterator->description);
        else
            DEBUG_PRINTF(LDBG, NULL, " (No description available).\n");
    }

    if( i == 0)
    {
        DEBUG_PRINTF(LDBG, NULL, "No interfaces found! Make sure WinPcap is installed.\n");
		return MCEDP_STATUS_GENERAL_FAIL;
    }
    
    
	if( EAF_CONFIG.INTERFACE_NUMBER < 1 || EAF_CONFIG.INTERFACE_NUMBER > i )
    {
        DEBUG_PRINTF(LDBG, NULL, "Interface number out of range.\n");
        pcap_freealldevs(DeviceList);
		return MCEDP_STATUS_GENERAL_FAIL;
    }
        
    // Jump to the selected adapter
    for( DeviceListIterator = DeviceList, i = 0; i < EAF_CONFIG.INTERFACE_NUMBER-1 ; DeviceListIterator = DeviceListIterator->next, i++ );
    
    
    // Open the device 
    if ( ( DeviceHandle = pcap_open(DeviceListIterator->name,			// name of the device
                                    65536,								// portion of the packet to capture
																	    // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
                                    1000,								// read timeout
                                    NULL,								// authentication on the remote machine
                                    ErrorInfo							// error buffer
                                    ) ) == NULL)
    {
        DEBUG_PRINTF(LDBG, NULL, "Unable to open the adapter. %s is not supported by WinPcap.\n", DeviceListIterator->name);
        pcap_freealldevs(DeviceList);
		return MCEDP_STATUS_GENERAL_FAIL;
    }

    DumpFile = pcap_dump_open( DeviceHandle, szPacketFilePath);

    if( DumpFile == NULL)
    {
        DEBUG_PRINTF(LDBG, NULL, "Error opening packet dump output file.\n");
        return -1;
    }
    
    // At this point, we no longer need the device list. Free it 
    pcap_freealldevs(DeviceList);
    
    // start the capture 
	pcap_loop( DeviceHandle, 0, PacketDumperCallback, (PUCHAR)DumpFile);

    return 0;
}
