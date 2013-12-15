#include"global.h"

proxySettings_t proxySettings = {0};
char* minerVersionString = "xptProxy v0.1";

int main()
{
	printf("\xC9\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xBB\n");
	printf("\xBA  xptProxy (v0.1c)                                \xBA\n");
	printf("\xBA  contributors: jh                                \xBA\n");
	printf("\xBA  local protocols: getwork(8332)                  \xBA\n");
	printf("\xBA  algorithms: scrypt                              \xBA\n");
	printf("\xC8\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xBC\n");
	printf("Launching proxy...\n");
	// init winsock
	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);
	// get IP of pool url (default ypool.net)
	char* poolURL = "ypool.net";
	hostent* hostInfo = gethostbyname(poolURL);
	if( hostInfo == NULL )
	{
		printf("Cannot resolve '%s'. Is it a valid URL?\n", poolURL);
		exit(-1);
	}
	void** ipListPtr = (void**)hostInfo->h_addr_list;
	uint32 ip = 0xFFFFFFFF;
	if( ipListPtr[0] )
	{
		ip = *(uint32*)ipListPtr[0];
	}
	char ipText[32];
	sprintf(ipText, "%d.%d.%d.%d", ((ip>>0)&0xFF), ((ip>>8)&0xFF), ((ip>>16)&0xFF), ((ip>>24)&0xFF));
	// set default proxy settings (todo: Add config)
	proxySettings.poolIP = ipText;
	proxySettings.poolPort = 10034;
	proxySettings.rpcPort = 8332;
	// init xpt proxy stuff
	xptProxy_init();
	// start json server thread
	printf("Starting JSON-RPC server on port %d...\n", proxySettings.rpcPort);
	jsonRpcServer_t* jrs = jsonRpc_createServer(proxySettings.rpcPort);
	if( jrs == NULL )
	{
		printf("Failed to open a server on port %d, try again\n", proxySettings.rpcPort);
		return -1;
	}
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jsonRpc_run, jrs, 0, NULL);
	// start processing xpt clients
	printf("xptProxy ready to accept connections!\n");
	xptProxy_mainloop();
	return 0;
}