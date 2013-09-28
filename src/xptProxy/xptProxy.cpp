#include"global.h"

typedef struct  
{
	uint64 workerIdHash;
	char workername[64];
	char workerpass[64];
	xptClient_t* xptClient;
	uint32 algorithm;
	uint32 coinbaseSeed;
	// cache timer
	uint32 timeCacheClear; // if this timer triggers, disconnect and free memory
	uint32 workerState;
	// delay notification
	bool delayNotifcationSend; // set to true once we informed all the waiting requests for about the state update
}xptProxyConnection_t;

#define WORKER_STATE_NEW		(1)		// proxy object was just created, no connection created yet
#define WORKER_STATE_CONNECT	(2)		// proxy object is trying to connect
#define WORKER_STATE_ERROR		(3)		// something went wrong, see error variable for more info
#define WORKER_STATE_AUTH		(5)		// proxy object is connected, waiting for worker auth
#define WORKER_STATE_ACTIVE		(6)		// logged in and ready to mine

simpleList_t* list_proxyConnections;

simpleList_t* list_workCache; // used to identify work

CRITICAL_SECTION cs_proxyConnections;
CRITICAL_SECTION cs_workCache;

typedef struct
{
	uint8 merkleroot[32];
	uint8 merklerootOriginal[32];
	uint32 time;
	// up to 16 bytes of user extra nonce
	uint8 userNonceLength;
	uint8 userNonceData[16];
}workCacheEntry_t;

/*
 * Adds an merkleroot -> user extra nonce pair to the work cache
 */
void xptProxyWorkCache_add(uint8* merkleroot, uint8* merklerootOriginal, uint32 userExtraNonceLength, uint8* userExtraNonceData)
{
	if( userExtraNonceLength > 16 )
		return; // user extra nonce data too long
	workCacheEntry_t* workCacheEntry = (workCacheEntry_t*)malloc(sizeof(workCacheEntry_t));
	memset(workCacheEntry, 0x00, sizeof(workCacheEntry_t));
	EnterCriticalSection(&cs_workCache);
	memcpy(workCacheEntry->merkleroot, merkleroot, 32);
	memcpy(workCacheEntry->merklerootOriginal, merklerootOriginal, 32);
	workCacheEntry->userNonceLength = userExtraNonceLength;
	memcpy(workCacheEntry->userNonceData, userExtraNonceData, userExtraNonceLength);
	simpleList_add(list_workCache, workCacheEntry);
	workCacheEntry->time = time(NULL) + (60*5); // data remains in cache for 5 minutes
	LeaveCriticalSection(&cs_workCache);
}

/*
 * Looks for the merkleroot and returns the associated user extra nonce data
 */
bool xptProxyWorkCache_find(uint8* merkleroot, uint8* merklerootOriginal, uint32* userExtraNonceLength, uint8* userExtraNonceData)
{
	EnterCriticalSection(&cs_workCache);
	for(uint32 i=0; i<list_workCache->objectCount; i++)
	{
		workCacheEntry_t* workCacheEntry = (workCacheEntry_t*)simpleList_get(list_workCache, i);
		if( memcmp(workCacheEntry->merkleroot, merkleroot, 32) == 0 )
		{
			// work found
			*userExtraNonceLength = workCacheEntry->userNonceLength;
			memcpy(userExtraNonceData, workCacheEntry->userNonceData, workCacheEntry->userNonceLength);
			memcpy(merklerootOriginal, workCacheEntry->merklerootOriginal, 32);
			LeaveCriticalSection(&cs_workCache);
			return true;
		}
	}
	LeaveCriticalSection(&cs_workCache);
	return false;
}

/*
 * Removes all outdated entries from the work cache
 */
void xptProxyWorkCache_cleanup()
{
	uint32 currentTime = time(NULL);
	EnterCriticalSection(&cs_workCache);
	for(uint32 i=0; i<list_workCache->objectCount; i++)
	{
		workCacheEntry_t* workCacheEntry = (workCacheEntry_t*)simpleList_get(list_workCache, i);
		if( currentTime >= workCacheEntry->time )
		{
			free(workCacheEntry);
			// remove element from list
			list_workCache->objects[i] = list_workCache->objects[list_workCache->objectCount-1];
			list_workCache->objectCount--;
			i--;
		}
	}
	LeaveCriticalSection(&cs_workCache);
}

/*
 * Simple and fast method for generating a hash based on the workername + workerpass
 */
uint64 xptProxy_generateWorkerHash(char* workername, char* workerpass)
{
	uint64 h = 0x5244748296f1f254ULL;
	// worker name
	while( *workername )
	{
		uint8 c = *workername;
		if( c >= 'A' && c <= 'Z' )
			c -= ('A'-'a');
		uint64 x = (uint64)c;
		h ^= x;
		h = (h<<61ULL) | (h>>3ULL);
		workername++;
	}
	// worker pass
	while( *workerpass )
	{
		uint8 c = *workerpass;
		if( c >= 'A' && c <= 'Z' )
			c -= ('A'-'a');
		uint64 x = (uint64)c;
		h ^= x;
		h = (h<<61ULL) | (h>>3ULL);
		workerpass++;
	}
	h ^= ((h<<17ULL) | (h>>(64ULL-17ULL)));
	h ^= ((h<<5ULL) | (h>>(64ULL-5ULL)));
	return h;
}

/*
 * Inits xpt proxy connection stuff
 */
void xptProxy_init()
{
	list_proxyConnections = simpleList_create(16);
	InitializeCriticalSection(&cs_proxyConnections);
	list_workCache = simpleList_create(16);
	InitializeCriticalSection(&cs_workCache);
}

#define CACHE_TIME_WORKER	(5*60*1000)	// workers remain with active connection for 5 minutes without interaction

void xptProxy_createConnectionObject(char* workername, char* workerpass)
{
	xptProxyConnection_t* xpc = (xptProxyConnection_t*)malloc(sizeof(xptProxyConnection_t));
	memset(xpc, 0x00, sizeof(xptProxyConnection_t));
	// initialize xpc struct
	strcpy(xpc->workername, workername);
	strcpy(xpc->workerpass, workerpass);
	xpc->workerIdHash = xptProxy_generateWorkerHash(workername, workerpass);
	xpc->algorithm = 0xFFFFFFFF;
	xpc->timeCacheClear = GetTickCount() + CACHE_TIME_WORKER;
	xpc->workerState = WORKER_STATE_NEW;
	// add to global list of known workers
	//EnterCriticalSection(&cs_proxyConnections);
	simpleList_add(list_proxyConnections, xpc);
	//LeaveCriticalSection(&cs_proxyConnections);
}

/*
 * Frees the xpc object but does not remove it from the list
 */
void xptProxy_freeConnectionObject(xptProxyConnection_t* xpc)
{
	if( xpc->xptClient )
		xptClient_free(xpc->xptClient);
	free(xpc);
}


/*
 * All-in-one command, for connect->xpt_getwork->generate_work
 */
void xptProxy_tryGenerateWork(char* workername, char* workerpass, xptProxyWorkData_t* workData)
{
	// find worker entry
	EnterCriticalSection(&cs_proxyConnections);
	xptProxyConnection_t* xpc = NULL;
	memset(workData, 0x00, sizeof(xptProxyWorkData_t));
	for(uint32 i=0; i<list_proxyConnections->objectCount; i++)
	{
		xptProxyConnection_t* xpcItr = (xptProxyConnection_t*)simpleList_get(list_proxyConnections, i);
		if( strcmp(xpcItr->workername, workername) == 0 )
		{
			xpc = xpcItr;
			break;
		}
	}
	if( xpc == NULL )
	{
		// create worker object
		xptProxy_createConnectionObject(workername, workerpass);
		workData->shouldTryAgain = true;
		workData->errorCode = PROXY_ERROR_WORKER_UNKNOWN;
	}
	else
	{
		// check state of object
		// is disconnected?
		if( xpc->xptClient == NULL || xpc->xptClient->disconnected )
		{
			if( xpc->xptClient != NULL )
			{
				if( xpc->xptClient->clientState != XPT_CLIENT_STATE_LOGGED_IN )
				{
					workData->errorCode = PROXY_ERROR_WORKER_AUTHFAILED;
				}
				else
				{
					workData->errorCode = PROXY_ERROR_WORKER_DISCONNECTED;
				}
			}
			else
			{
				workData->shouldTryAgain = true;
				workData->errorCode = PROXY_ERROR_WORKER_UNINITIALIZED;
			}
			workData->shouldTryAgain = false;
		}
		else if( xpc->xptClient->clientState == XPT_CLIENT_STATE_LOGGED_IN )
		{
			// worker is logged in and running
			// have we already received work?
			if( xpc->xptClient->hasWorkData > 0 )
			{
				workData->algorithm = xpc->algorithm;
				// copy work data
				workData->height = xpc->xptClient->blockWorkInfo.height;
				workData->version = xpc->xptClient->blockWorkInfo.version;
				uint32 timeBias = time(NULL) - xpc->xptClient->blockWorkInfo.timeWork;
				workData->nTime = xpc->xptClient->blockWorkInfo.nTime + timeBias;
				workData->nBits = xpc->xptClient->blockWorkInfo.nBits;
				memcpy(workData->merkleRootOriginal, xpc->xptClient->blockWorkInfo.merkleRoot, 32);
				memcpy(workData->prevBlockHash, xpc->xptClient->blockWorkInfo.prevBlockHash, 32);
				memcpy(workData->target, xpc->xptClient->blockWorkInfo.target, 32);
				memcpy(workData->targetShare, xpc->xptClient->blockWorkInfo.targetShare, 32);
				// generate unique work from custom extra nonce
				uint32 userExtraNonce = xpc->coinbaseSeed;
				xpc->coinbaseSeed++;
				bitclient_generateTxHash(sizeof(uint32), (uint8*)&userExtraNonce, xpc->xptClient->blockWorkInfo.coinBase1Size, xpc->xptClient->blockWorkInfo.coinBase1, xpc->xptClient->blockWorkInfo.coinBase2Size, xpc->xptClient->blockWorkInfo.coinBase2, xpc->xptClient->blockWorkInfo.txHashes);
				bitclient_calculateMerkleRoot(xpc->xptClient->blockWorkInfo.txHashes, xpc->xptClient->blockWorkInfo.txHashCount+1, workData->merkleRoot);
				workData->errorCode = 0;
				workData->shouldTryAgain = false;
				xpc->timeCacheClear = GetTickCount() + CACHE_TIME_WORKER;
				xptProxyWorkCache_add(workData->merkleRoot, workData->merkleRootOriginal, sizeof(uint32), (uint8*)&userExtraNonce);
			}
			else
			{
				workData->errorCode = PROXY_ERROR_WORKER_NOWORK;
				workData->shouldTryAgain = true;
			}
		}
		else
		{
			workData->errorCode = PROXY_ERROR_WORKER_NOWORK;
			workData->shouldTryAgain = true;
		}
	}
	LeaveCriticalSection(&cs_proxyConnections);
}

/*
 * Return work data associated with the merkleroot
 */
bool xptProxy_submitData(char* workername, uint8* blockData, uint32 blockDataLength)
{
	// try to find the worker
	EnterCriticalSection(&cs_proxyConnections);
	xptProxyConnection_t* xpc = NULL;
	for(uint32 i=0; i<list_proxyConnections->objectCount; i++)
	{
		xptProxyConnection_t* xpcItr = (xptProxyConnection_t*)simpleList_get(list_proxyConnections, i);
		if( strcmp(xpcItr->workername, workername) == 0 )
		{
			xpc = xpcItr;
			break;
		}
	}
	if( xpc == NULL || xpc->xptClient == NULL )
	{
		LeaveCriticalSection(&cs_proxyConnections);
		return false; // worker not found, cannot accept share
	}
	// worker found, get algorithm
	if( xpc->algorithm == ALGORITHM_SCRYPT )
	{
		// we need to reverse the endianness of the block data
		uint8 proofOfWorkHash[32];
		for(uint32 f=0; f<128/4; f++)
		{
			*(uint32*)(blockData+f*4) = _swapEndianessU32(*(uint32*)(blockData+f*4));
		}
		scrypt_1024_1_1_256((const char*)blockData, (char*)proofOfWorkHash);
		uint32* generatedHash32 = (uint32*)proofOfWorkHash;
		uint32* targetHash32 = (uint32*)xpc->xptClient->blockWorkInfo.targetShare;
		bool hashMeetsTarget = true;
		for(sint32 hc=7; hc>=0; hc--)
		{
			if( generatedHash32[hc] < targetHash32[hc] )
			{
				hashMeetsTarget = true;
				break;
			}
			else if( generatedHash32[hc] > targetHash32[hc] )
			{
				hashMeetsTarget = false;
				break;
			}
		}
		if( hashMeetsTarget == false )
		{
			// share not good enough
			LeaveCriticalSection(&cs_proxyConnections);
			return false;
		}
		// find original work
		uint8 merklerootOriginal[32];
		uint32 userExtraNonceLength;
		uint8 userExtraNonceData[16];
		if( xptProxyWorkCache_find(blockData+4+32, merklerootOriginal, &userExtraNonceLength, userExtraNonceData) == false )
		{
			// work could not be identified
			printf("xptProxy_submitData(): Worker %s submitted block that references to unknown work\n", workername);
			LeaveCriticalSection(&cs_proxyConnections);
			return false;
		}
		// submit block
		xptShareToSubmit_t* xptShare = (xptShareToSubmit_t*)malloc(sizeof(xptShareToSubmit_t));
		memset(xptShare, 0x00, sizeof(xptShareToSubmit_t));
		xptShare->algorithm = xpc->algorithm;
		xptShare->version = _swapEndianessU32(*(uint32*)(blockData+0));
		xptShare->nTime = _swapEndianessU32(*(uint32*)(blockData+4+32+32));
		xptShare->nonce = _swapEndianessU32(*(uint32*)(blockData+12+32+32));
		xptShare->nBits = _swapEndianessU32(*(uint32*)(blockData+8+32+32));
		memcpy(xptShare->prevBlockHash, blockData+4, 32);
		memcpy(xptShare->merkleRoot, blockData+4+32, 32);
		memcpy(xptShare->merkleRootOriginal, merklerootOriginal, 32);
		userExtraNonceLength = min(userExtraNonceLength, 16);
		xptShare->userExtraNonceLength = userExtraNonceLength;
		memcpy(xptShare->userExtraNonceData, userExtraNonceData, userExtraNonceLength);
		xptClient_foundShare(xpc->xptClient, xptShare);
	}
	else
	{
		// unknown algoritm :(
		printf("xptProxy_submitData(): Worker %s uses unknown algorithm\n", workername);
		LeaveCriticalSection(&cs_proxyConnections);
		return false; // worker not found, cannot accept share
	}
	LeaveCriticalSection(&cs_proxyConnections);
	return true;
}

/*
 * Trys to establish a xpt connection to the given worker
 */
int xptProxy_asyncConnect(xptProxyConnection_t* xpc)
{
	generalRequestTarget_t connectionTarget = {0};
	connectionTarget.ip = proxySettings.poolIP;
	connectionTarget.port = proxySettings.poolPort;
	connectionTarget.authUser = xpc->workername;
	connectionTarget.authPass = xpc->workerpass;
	xptClient_t* xptClient = xptClient_connect(&connectionTarget, 0);
	// since this method is called in a separate thread, do not set state&xptClient variable until everything is initialized
	if( xptClient == NULL )
	{
		xpc->workerState = WORKER_STATE_ERROR;
		xpc->timeCacheClear = GetTickCount() + 30*1000; // remove this instance from cache and try again in 30 seconds
	}
	else
	{
		xpc->workerState = WORKER_STATE_AUTH;
		xpc->xptClient = xptClient;
	}
	return 0;
}

/*
 * xptProxy processing loop
 */
void xptProxy_mainloop()
{
	uint32 timer_workCacheCleanup = GetTickCount() + 25000;
	while( true )
	{
		// process all open connections
		for(uint32 i=0; i<list_proxyConnections->objectCount; i++)
		{
			xptProxyConnection_t* xpcItr = (xptProxyConnection_t*)simpleList_get(list_proxyConnections, i);
			if( xpcItr->xptClient )
			{
				xptClient_process(xpcItr->xptClient);
				if( xpcItr->workerState == WORKER_STATE_AUTH && xpcItr->xptClient->hasWorkData )
				{
					xpcItr->algorithm = xpcItr->xptClient->algorithm;
					xpcItr->workerState = WORKER_STATE_ACTIVE;
				}
			}
		}
		// handle all new connects
		EnterCriticalSection(&cs_proxyConnections);
		sint32 connectLimit = 3;
		for(uint32 i=0; i<list_proxyConnections->objectCount; i++)
		{
			xptProxyConnection_t* xpcItr = (xptProxyConnection_t*)simpleList_get(list_proxyConnections, i);
			if( xpcItr->xptClient == NULL && xpcItr->workerState == WORKER_STATE_NEW )
			{
				xpcItr->workerState = WORKER_STATE_CONNECT;
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)xptProxy_asyncConnect, xpcItr, 0, NULL);
				connectLimit--;
				if( connectLimit <= 0 )
					break;
			}
		}
		LeaveCriticalSection(&cs_proxyConnections);
		// handle all error connections
		EnterCriticalSection(&cs_proxyConnections);
		for(uint32 i=0; i<list_proxyConnections->objectCount; i++)
		{
			xptProxyConnection_t* xpcItr = (xptProxyConnection_t*)simpleList_get(list_proxyConnections, i);
			if( xpcItr->xptClient && xpcItr->xptClient->disconnected && xpcItr->workerState != WORKER_STATE_ERROR )
			{
				if( xpcItr->xptClient )
				{
					xptClient_free(xpcItr->xptClient);
					xpcItr->xptClient = NULL;
				}
				xpcItr->timeCacheClear = GetTickCount() + 15000; // workers with an connection problem will be deleted faster (since we do not support auto-reconnect)
				xpcItr->workerState = WORKER_STATE_ERROR;
			}
		}
		LeaveCriticalSection(&cs_proxyConnections);
		// check for silent workers or workers with errors
		EnterCriticalSection(&cs_proxyConnections);
		uint32 currentTick = GetTickCount();
		for(uint32 i=0; i<list_proxyConnections->objectCount; i++)
		{
			xptProxyConnection_t* xpcItr = (xptProxyConnection_t*)simpleList_get(list_proxyConnections, i);
			if( currentTick >= xpcItr->timeCacheClear )
			{
				// worker was not used for some time -> delete it
				xptProxy_freeConnectionObject(xpcItr);
				// remove from list
				list_proxyConnections->objects[i] = list_proxyConnections->objects[list_proxyConnections->objectCount-1];
				list_proxyConnections->objectCount--;
				i--;
			}
		}
		LeaveCriticalSection(&cs_proxyConnections);
		// check work cache
		currentTick = GetTickCount();
		if( currentTick >= timer_workCacheCleanup )
		{
			xptProxyWorkCache_cleanup();
			timer_workCacheCleanup = currentTick + 25000;
		}
		Sleep(1);
	}
}