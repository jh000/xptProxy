#include"global.h"

uint32 _getHexDigitValue(uint8 c)
{
	if( c >= '0' && c <= '9' )
		return c-'0';
	else if( c >= 'a' && c <= 'f' )
		return c-'a'+10;
	else if( c >= 'A' && c <= 'F' )
		return c-'A'+10;
	return 0;
}

/*
 * Parses a hex string
 * Length should be a multiple of 2
 */
void xptProxy_parseHexString(char* hexString, uint32 length, uint8* output)
{
	uint32 lengthBytes = length / 2;
	for(uint32 i=0; i<lengthBytes; i++)
	{
		// high digit
		uint32 d1 = _getHexDigitValue(hexString[i*2+0]);
		// low digit
		uint32 d2 = _getHexDigitValue(hexString[i*2+1]);
		// build byte
		output[i] = (uint8)((d1<<4)|(d2));	
	}
}

/*
 * Parses a hex string and converts it to LittleEndian
 * Length should be a multiple of 2
 */
void xptProxy_parseHexStringLE(char* hexString, uint32 length, uint8* output)
{
	uint32 lengthBytes = length / 2;
	for(uint32 i=0; i<lengthBytes; i++)
	{
		// high digit
		uint32 d1 = _getHexDigitValue(hexString[i*2+0]);
		// low digit
		uint32 d2 = _getHexDigitValue(hexString[i*2+1]);
		// build byte
		output[lengthBytes-i-1] = (uint8)((d1<<4)|(d2));	
	}
}

void jsonRpc_processRequest_getwork_sendWorkData(jsonRpcServer_t* jrs, jsonRpcClient_t* client, xptProxyWorkData_t* workData)
{
	// build response using current work data
	//{
	//	"midstate" : "e800855353e1038a7366ad018c36547f0acc80798f1dc187b68e2e372d64452d",
	//		"data" : "0000000157a22cd24fe50e6a2269fd98fa08d479818023aecf9becb9e196c61ba1f9d8eac25c0399a04e5edefdc860e878881370ea241bfd6c6058d6a76f06370c53403051ccc41c1c02a17e00000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000",
	//		"hash1" : "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000",
	//		"target" : "000000000000000000000000000000000000000000000000007ea10200000000",
	//		"algorithm" : "scrypt:1024,1,1"
	//}
	fStr_buffer4kb_t fStrBuffer_response;
	fStr_t* fStr_response = fStr_alloc(&fStrBuffer_response, FSTR_FORMAT_UTF8);
	uint8 blockRawData[512];
	// update timestamp (todo) and set nonce to zero per default
	uint32 newTimestamp = workData->nTime;
	*(uint32*)(blockRawData+4+32+32) = (newTimestamp);
	uint32 newNonce = 0; // always zero
	*(uint32*)(blockRawData+12+32+32) = (newNonce);
	// set block version
	*(uint32*)(blockRawData+0) = (workData->version);
	// set block nBits
	*(uint32*)(blockRawData+8+32+32) = (workData->nBits);
	// set prevblockhash and merkleroot
	memcpy(blockRawData+4, workData->prevBlockHash, 32);
	memcpy(blockRawData+4+32, workData->merkleRoot, 32);
	//	// swap endianness
	for(uint32 f=0; f<sizeof(blockRawData)/4; f++)
	{
		*(uint32*)(blockRawData+f*4) = _swapEndianessU32(*(uint32*)(blockRawData+f*4));
	}
	// format and append to response
	fStr_appendFormatted(fStr_response, "{\"data\":\"");
	fStr_addHexString(fStr_response, blockRawData, 128);
	fStr_appendFormatted(fStr_response, "\",\"target\":\"");
	fStr_addHexString(fStr_response, workData->targetShare, 32);
	fStr_appendFormatted(fStr_response, "\",\"algorithm\":\"scrypt:1024,1,1\"}");
	// set header fields used for extensions
	char* additionalHeaderData = "X-Long-Polling: /longpoll\r\n";
	// send response
	jsonRpc_sendResponseRaw(jrs, client, fStr_response, additionalHeaderData);
}

/*
 * Called when a client calls "getwork"
 * JSON parameters: client->lastRequestJsonParameter
 */
void jsonRpc_processRequest_getwork(jsonRpcServer_t* jrs, jsonRpcClient_t* client, bool isDelayed)
{
	if( strlen(client->httpAuthUsername) > 64 )
		client->httpAuthUsername[63] = '\0';
	if( strlen(client->httpAuthPassword) > 64 )
		client->httpAuthPassword[63] = '\0';
	// ignore starting '/' of call path
	if( client->callPathLength > 0 && client->callPath[0] == '/' )
	{
		client->callPath++;
		client->callPathLength--;
	}
	// check if longpoll mode
	if( client->longpollActive || (client->callPath && client->callPathLength >= 8 && memcmp(client->callPath, "longpoll", 8) == 0) )
	{
		// long poll mode
		xptProxyWorkData_t workData = {0};
		// check if we need to initate the request
		if( client->longpollActive == false )
		{
			//printf("[DEBUG] Starting poll\n");
			// generate work to get block height
			xptProxy_tryGenerateWork(client->httpAuthUsername, client->httpAuthPassword, &workData, true);
			if( workData.shouldTryAgain == true )
			{
				jsonRpc_delayRequestByTime(jrs, client, NULL, 500, jsonRpc_processRequest_getwork);
				return;
			}	
			client->longpollActive = true;
			client->longpollBlockHeight = workData.height;
			jsonRpc_delayRequestByTime(jrs, client, NULL, 300, jsonRpc_processRequest_getwork);
			return;
		}
		// after init, this method will be called with the same parameters every 300ms
		xptProxy_tryGenerateWork(client->httpAuthUsername, client->httpAuthPassword, &workData, true);
		if( workData.shouldTryAgain == true )
		{
			// connection problem or other xpt error
			jsonRpc_delayRequestByTime(jrs, client, NULL, 500, jsonRpc_processRequest_getwork);
			return;
		}
		if( client->longpollBlockHeight == workData.height )
		{
			// still same block, call this method again in 300ms
			jsonRpc_delayRequestByTime(jrs, client, NULL, 300, jsonRpc_processRequest_getwork); // this method will get called again in 500ms
			return;
		}
		printf("Longpoll detected new block height %d\n", workData.height);
		client->longpollActive = false;
	}
	

	// did the miner submit a share?
	jsonObject_t* jsonClientData = jsonObject_getArrayElement(client->lastRequestJsonParameter, 0);
	if( jsonClientData )
	{
		if( jsonObject_getType(jsonClientData) == JSON_TYPE_STRING )
		{
			uint32 dataHexStringLength = 0;
			uint8* dataHexStringPtr = jsonObject_getStringData(jsonClientData, &dataHexStringLength);
			if( dataHexStringPtr && dataHexStringLength >= 80*2 ) // its actually very unlikely this will fail, but just to be sure...
			{
				uint8 dataRaw[512];
				RtlZeroMemory(dataRaw, sizeof(dataRaw));
				xptProxy_parseHexString((char*)dataHexStringPtr, min(512*2, dataHexStringLength), dataRaw);
				uint32 rawDataLength = min(512*2, dataHexStringLength)/2;
				bool shareAccepted = xptProxy_submitData(client->httpAuthUsername, dataRaw, rawDataLength);

				fStr_buffer4kb_t fStrBuffer_response;
				fStr_t* fStr_response = fStr_alloc(&fStrBuffer_response, FSTR_FORMAT_UTF8);
				if( shareAccepted )
					fStr_appendFormatted(fStr_response, "true");
				else
					fStr_appendFormatted(fStr_response, "false");
				char* additionalHeaderData = "X-Long-Polling: /longpoll\r\n";
				jsonRpc_sendResponseRaw(jrs, client, fStr_response, additionalHeaderData);
				return;
			}
			else
				printf("getwork: Client sent invalid share data\n");
		}
	}
	// no data submitted -> generate new work
	xptProxyWorkData_t workData = {0};
	xptProxy_tryGenerateWork(client->httpAuthUsername, client->httpAuthPassword, &workData);
	if( workData.shouldTryAgain == true )
	{
		jsonRpc_delayRequestByTime(jrs, client, NULL, 500, jsonRpc_processRequest_getwork); // this method will get called again in 500ms
		return;
	}	
	else
	{
		if( workData.errorCode != 0 )
		{
			return; // todo -> Send error to miner
		}
		jsonRpc_processRequest_getwork_sendWorkData(jrs, client, &workData);
	}
}