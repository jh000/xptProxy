#pragma comment(lib,"Ws2_32.lib")
#include<Winsock2.h>
#include<ws2tcpip.h>
#include"jhlib/JHLib.h"

#include<stdio.h>
#include<time.h>

#include"sha256.h"
#include"scrypt.h"
#include"jsonrpc.h"

//#include<stdint.h> - not present in vs2008 install, instead we have the types below:
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef __int64 int64_t;

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;

#include"xptServer.h"
#include"xptClient.h"

typedef struct  
{
	char*	poolIP;
	uint16	poolPort;
	uint16	rpcPort;
}proxySettings_t;

extern proxySettings_t proxySettings;

#include"xptProxy.h"

#include"transaction.h"

static uint32 _swapEndianessU32(uint32 v)
{
	return ((v>>24)&0xFF)|((v>>8)&0xFF00)|((v<<8)&0xFF0000)|((v<<24)&0xFF000000);
}

static void __debug__printHex(uint8* hexStr, int len)
{
	for(uint32 i=0; i<len; i++)
	{
		printf("%02x", hexStr[i]);
	}
}