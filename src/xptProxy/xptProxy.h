void xptProxy_init();
void xptProxy_mainloop();


#define PROXY_ERROR_WORKER_UNKNOWN			(1)
#define PROXY_ERROR_WORKER_AUTHFAILED		(2)
#define PROXY_ERROR_WORKER_DISCONNECTED		(3)
#define PROXY_ERROR_WORKER_NOWORK			(4)	// no work received yet
#define PROXY_ERROR_WORKER_UNINITIALIZED	(5) // unknown worker state (no xptClient instance exists)

typedef struct  
{
	uint32 errorCode;
	bool shouldTryAgain; // notifies the caller that the method should be called again (delayed request)
	uint32 algorithm;
	// block data
	uint32 height;
	uint32 version;
	uint32 nTime;
	uint32 nBits;
	uint32 nBitsShare;
	uint8 merkleRoot[32];
	uint8 prevBlockHash[32];
	uint8 target[32];
	uint8 targetShare[32];
	// the original merkleRoot (used by server to identify work)
	uint8 merkleRootOriginal[32];
}xptProxyWorkData_t;

void xptProxy_tryGenerateWork(char* workername, char* workerpass, xptProxyWorkData_t* workData, bool generateOnlyBlockHeader=false);
bool xptProxy_submitData(char* workername, uint8* blockData, uint32 blockDataLength);