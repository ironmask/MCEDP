#include "XmlLog.h"

PXMLNODE
NewXmlRoot(
	IN CONST PCHAR Name
	)
{
	return ( mxmlNewXML(Name) );
}

PXMLNODE
CreateXmlElement(
	IN PXMLNODE ParentXmlNode,
	IN CONST PCHAR Name
	)
{
	return (mxmlNewElement( ParentXmlNode, Name ) );
}

PXMLNODE
SetTextNode(
	IN PXMLNODE ParentXmlNode,
	IN DWORD WhiteSpace,
	IN CONST PCHAR Value
	)
{
	return ( mxmlNewText( ParentXmlNode, WhiteSpace, Value) );
}

STATUS
SaveXml(
	IN PXMLNODE TopElement
	)
{
	FILE *fp;
	ERRORINFO err;
	CHAR szLogDir[MAX_PATH];
	CHAR szShellcodeFile[MAX_PATH];

	strncpy(szLogDir, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH);
	sprintf(szShellcodeFile, "\\ShellocdeAnalysis.xml");
	strncat(szLogDir, szShellcodeFile , MAX_PATH);

    fp = fopen(szLogDir, "w");

	if ( fp == NULL )
	{
		REPORT_ERROR("fopen()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

    if ( mxmlSaveFile(TopElement, fp, MXML_NO_CALLBACK) == -1 )
	{
		REPORT_ERROR("mxmlSaveFile()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

    fclose(fp);
	return MCEDP_STATUS_SUCCESS;
}