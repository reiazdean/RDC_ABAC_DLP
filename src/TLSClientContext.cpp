/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "threadPool.h"
#include "NdacConfig.h"
#include "x509class.h"
#include "clusterServiceManager.h"
#include "clusterClientManager.h"
#include "TLSClientContext.h"


using namespace ReiazDean;

std::vector<std::pair<Buffer, Buffer>> TLSClientContext::s_Hosts2IpAdrs;
SSL_CTX* TLSClientContext::s_ctx = TLSClientContext::CreateContext();

SSL_CTX* TLSClientContext::CreateContext()
{
	SSL_CTX* ctx = nullptr;
	SSL_METHOD* meth;
	Buffer bCAcert;
#ifdef AUTH_SERVICE
	NdacServerConfig& pConf = NdacServerConfig::GetInstance();
	ClusterServiceManager& cm = ClusterServiceManager::GetInstance();
#else
	NdacClientConfig& pConf = NdacClientConfig::GetInstance();
	ClusterClientManager& cm = ClusterClientManager::GetInstance();
#endif

	pConf.GetValue(TRUSTED_CA_FILE, bCAcert);

	meth = (SSL_METHOD*)TLS_client_method();
	if (meth) {
		ctx = SSL_CTX_new(meth);
	}

	if (ctx) {
		SSL_CTX_set_cipher_list(ctx, "AES256-SHA");
		if (SSL_CTX_load_verify_locations(ctx, (char*)bCAcert, 0)) {
			SSL_CTX_set_verify_depth(ctx, 1);
			return ctx;
		}
	}
	//if we got here TLS fails
	return nullptr;
}

void TLSClientContext::Finalize()
{
	if (s_ctx) {
		SSL_CTX_free(s_ctx);
	}
}

/******************************************************************************************
Constructor			TLSClientContext(char* hostname, int port)
Parameters:			(char* hostname, int port)

Description:		Construct an instance with specified inputs

*******************************************************************************************/
TLSClientContext::TLSClientContext() : TLSContext()
{
}

/******************************************************************************************
Destructor			~TLSClientContext()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
TLSClientContext::~TLSClientContext()
{
}

void TLSClientContext::Map(Buffer bHost, Buffer bIP)
{
	std::unique_lock<std::mutex> mlock(s_MutexVar);
	s_Hosts2IpAdrs.push_back(std::pair<Buffer, Buffer>(bHost, bIP));
}

bool TLSClientContext::GetIP(Buffer bHost, Buffer& bIP)
{
	bIP.Clear();
	try {
		std::unique_lock<std::mutex> mlock(s_MutexVar);
		for (const auto& aPair : s_Hosts2IpAdrs) {
			Buffer b = aPair.first;
			if (strcmp((char*)bHost, (char*)b) == 0) {
				bIP = aPair.second;
				return true;
			}
		}
	}
	catch (...) {
		bIP.Clear();
		return false;
	}

	return false;
}

bool TLSClientContext::GetHostAddrMapping(Buffer bIn, Buffer& bOut)
{
	if (GetIP(bIn, bOut)) {
		return true;
	}

	if (GetHostAddrInfo(bIn, bOut)) {
		Map(bIn, bOut);
		return true;
	}
	return false;
}

/******************************************************************************************
Function Name:		DoClientNoCert()
Parameters:			none

Description:		Initialize the SSL context

*******************************************************************************************/
Responses TLSClientContext::DoClientNoCert()
{
	Buffer           port;
	int              iPort = 0;
#ifdef AUTH_SERVICE
	NdacServerConfig& pConf = NdacServerConfig::GetInstance();
	ClusterServiceManager& cm = ClusterServiceManager::GetInstance();
#else
	NdacClientConfig& pConf = NdacClientConfig::GetInstance();
	ClusterClientManager& cm = ClusterClientManager::GetInstance();
#endif

	pConf.GetValue(TLS_PORT_STRING, port);
	iPort = atoi((char*)port);
	if (cm.RoundRobin(m_bHost) && (m_bHost.Size() > 0)) {
		Buffer bIP;
		m_sock = 0;
		if (GetHostAddrMapping(m_bHost, bIP)) {
			m_sock = OpenClientInetSocket((char*)bIP, iPort);
		}
		if (m_sock <= 0) {
			cm.FailMember((char*)m_bHost);
			return RSP_FILE_ERROR;
		}
		return RSP_SUCCESS;
	}

	return RSP_SOCKET_IO_ERROR;
}

/******************************************************************************************
Function Name:		DoClusterClientNoCert(char* pcMemberIP)
Parameters:			none

Description:		Initialize the SSL context

*******************************************************************************************/
Responses TLSClientContext::DoClusterClientNoCert(char* pcMemberIP)
{
	Buffer           port;
	int              iPort = 0;
#ifdef AUTH_SERVICE
	NdacServerConfig& pConf = NdacServerConfig::GetInstance();
	ClusterServiceManager& cm = ClusterServiceManager::GetInstance();
#else
	NdacClientConfig& pConf = NdacClientConfig::GetInstance();
	ClusterClientManager& cm = ClusterClientManager::GetInstance();
#endif

	pConf.GetValue(TLS_PORT_STRING, port);
	iPort = atoi((char*)port);
	if (pcMemberIP) {
		m_bHost.Clear();
		m_bHost.Append(pcMemberIP, (int32_t)strlen(pcMemberIP));
		m_bHost.NullTerminate();
		Buffer bIP;
		m_sock = 0;
		if (GetHostAddrMapping(m_bHost, bIP)) {
			m_sock = OpenClientInetSocket((char*)bIP, iPort);
		}
		if (m_sock <= 0) {
			cm.FailMember((char*)m_bHost);
			return RSP_FILE_ERROR;
		}
		return RSP_SUCCESS;
	}

	return RSP_SOCKET_IO_ERROR;
}

/******************************************************************************************
Function Name:		EstablishClientSSL(  )
Parameters:			int sock

Description:		Establish a SSL context

*******************************************************************************************/
Responses TLSClientContext::EstablishClient()
{
	int        r;
	int        err = SSL_ERROR_WANT_READ;
	int        tries = 0;

	if (!s_ctx) {
		return RSP_NULL;//FIXME
	}

	SetToNotBlock(m_sock);
	m_ssl = SSL_new(s_ctx);
	if (!m_ssl) {
		return RSP_NULL;//FIXME
	}
	SSL_set_fd(m_ssl, (int)m_sock);

	while ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) && tries < MAX_WANT_TRIES)
	{
		r = SSL_connect(m_ssl);
		err = SSL_get_error(m_ssl, r);
		tries++;
		if (r <= 0)
		{
			r = Select(m_sock, 0, 1000000, true);
		}
	}
	
	if (r <= 0)
	{
		return RSP_NULL;//FIXME
	}
	
	return RSP_SUCCESS;
}

Responses TLSClientContext::PartiallyEstablishClient()
{
	return EstablishClient();
}

Responses TLSClientContext::EstablishClusterClient()
{
	Responses r = EstablishClient();

	if (r == RSP_SUCCESS) {
		return ExchangeKyber();
	}

	return r;
}

Responses TLSClientContext::FullyEstablishClient()
{
	Responses r = EstablishClient();

	if (r == RSP_SUCCESS) {
		r = ReadServerNonce();
	}

	if (r == RSP_SUCCESS) {
		r = ExchangeKyber();
	}

	if (r == RSP_SUCCESS) {
		return ValidateNodeSecret();
	}

	return r;
}

Responses TLSClientContext::ReadServerNonce()
{
	CommandHeader ch;
	Buffer cmd;
	Buffer resp;

	try {
		ch.command = CMD_GET_SERVER_NONCE;
		ch.szData = 0;
		cmd.Append((void*)&ch, sizeof(ch));
		ExecuteCommand(cmd, resp);
		if (resp.Size() >= sizeof(ResponseHeader)) {
			ResponseHeader* rh = (ResponseHeader*)resp;
			if (rh && (rh->response == RSP_SUCCESS) && (rh->szData == sizeof(m_nonce))) {
				uint8_t* pChar = (uint8_t*)resp + sizeof(ResponseHeader);
				memcpy(m_nonce, pChar, rh->szData);
				return RSP_SUCCESS;
			}
		}
	}
	catch (...) {
		return RSP_NULL;
	}

	return RSP_MEMORY_ERROR;
}

#ifdef _DEBUGXXX
static Buffer BSig;
static Certificate sCert;
Responses TLSClientContext::SignNodeSecretAndNonce(Buffer& bInOut)
{
	Buffer cert;
	std::unique_lock<std::mutex> mlock(s_MutexVar);
	if (BSig.Size() == 0) {
		if (KSPSign(ChooseUserKey(), bInOut, cert)) {
			m_Certificate = Certificate(cert);
			BSig = bInOut;
			sCert = m_Certificate;
			return RSP_SUCCESS;
		}
	}
	else {
		bInOut = BSig;
		m_Certificate = sCert;
		return RSP_SUCCESS;
	}
	return RSP_SIGNATURE_INVALID;
}
#else
Responses TLSClientContext::SignNodeSecretAndNonce(Buffer& bInOut)
{
	Buffer cert;
	if (KSPSign(ChooseUserKey(), bInOut, cert)) {
		Certificate c(cert);
		m_Certificate = c;
		return RSP_SUCCESS;
	}
	return RSP_SIGNATURE_INVALID;
}
#endif

Responses TLSClientContext::ValidateNodeSecret()
{
	bool bRc = false;
	CommandHeader ch;
	Buffer cmd;
	Buffer resp;
	ResponseHeader* prh = nullptr;

	try {
		Buffer b;
		
		b.Append(m_nonce, sizeof(m_nonce));
		if (RSP_SUCCESS == SignNodeSecretAndNonce(b)) {
			ch.command = CMD_SEND_NODE_SECRET;
			ch.szData = b.Size();
			cmd.Append((void*)&ch, sizeof(ch));
			cmd.Append(b);
			ExecuteCommand(cmd, resp);
			if (resp.Size() >= sizeof(ResponseHeader)) {
				prh = (ResponseHeader*)resp;
				return prh->response;
			}
		}
	}
	catch (...) {
		return RSP_NULL;
	}

	return RSP_NOT_VALID_NODE;
}

Responses TLSClientContext::ExchangeKyber()
{
	CommandHeader ch;
	Buffer cmd;
	Buffer resp;

	try {
		if (0 == m_KyberKeyPair.Create()) {
			ch.command = CMD_EXCHANGE_KYBER_KEYS;
			ch.szData = m_KyberKeyPair.GetPublicKeySize();
			cmd.Append((void*)&ch, sizeof(ch));
			cmd.Append(m_KyberKeyPair.GetPublicKey(), m_KyberKeyPair.GetPublicKeySize());
			ExecuteCommand(cmd, resp);
			if (resp.Size() >= sizeof(ResponseHeader)) {
				ResponseHeader* rh = (ResponseHeader*)resp;
				if (rh && (rh->response == RSP_SUCCESS)) {
					Buffer bSig, bWrapped;
					SequenceReaderX seq;
					uint8_t* pChar = (uint8_t*)resp + sizeof(ResponseHeader);
					Buffer bMessage(pChar, rh->szData);
					seq.Initilaize(bMessage);
					seq.getElementAt(0, bWrapped);
					seq.getValueAt(1, bSig);
					if (s_DilithiumKeyPair.Verify(bWrapped, bSig)) {
						bWrapped.Clear();
						seq.getValueAt(0, bWrapped);
						if (m_KyberKeyPair.UnwrapAESKey(bWrapped) > 0) {
							return RSP_SUCCESS;
						}
					}
				}
			}
		}
	}
	catch (...) {
		return RSP_NULL;
	}

	return RSP_CIPHER_ERROR;
}

int32_t TLSClientContext::AES_Encrypt(uint8_t* plaintext, int32_t len, Buffer& bEnc)
{
	return m_KyberKeyPair.AES_Encrypt(plaintext, len, bEnc);
}

int32_t TLSClientContext::AES_Decrypt(uint8_t* ciphertext, int32_t len, Buffer& bPlain)
{
	return m_KyberKeyPair.AES_Decrypt(ciphertext, len, bPlain);
}

void TLSClientContext::LockPages()
{
	m_KyberKeyPair.LockPages();
}

void TLSClientContext::EndConnection()
{
	Shutdown();
}

Responses TLSClientContext::ExecuteCommand(Buffer cmd, Buffer& resp)
{
	int  len = -1;
	CommandHeader* pch;
	ResponseHeader* prh;
	ResponseHeader rh = { RSP_NULL, 0 };
#ifdef AUTH_SERVICE
	ClusterServiceManager& cm = ClusterServiceManager::GetInstance();
#else
	ClusterClientManager& cm = ClusterClientManager::GetInstance();
#endif

	resp.Clear();
	if (cmd.Size() >= sizeof(CommandHeader)) {
		pch = (CommandHeader*)cmd;
		if ((pch->command < 0) || (pch->command >= CMD_NULL)) {
			resp.Append((void*)&rh, sizeof(ResponseHeader));
			return RSP_INVALID_COMMAND;
		}
	}
	else {
		resp.Append((void*)&rh, sizeof(ResponseHeader));
		return RSP_MEMORY_ERROR;
	}

	len = DoNonBlockingWrite(cmd);
	if (len == cmd.Size()) {
		resp.Clear();
		len = DoNonBlockingRead(resp);
		if (len >= sizeof(ResponseHeader)) {
			prh = (ResponseHeader*)resp;
			if ((prh->response >= RSP_SUCCESS) && (prh->response < RSP_NULL)) {
				rh.response = prh->response;
			}
			else {
				resp.Append((void*)&rh, sizeof(ResponseHeader));
				cm.FailMember((char*)m_bHost);
			}
		}
		else {
			rh.response = RSP_SOCKET_IO_ERROR;
			resp.Append((void*)&rh, sizeof(ResponseHeader));
			cm.FailMember((char*)m_bHost);
		}
	}
	else {
		rh.response = RSP_SOCKET_IO_ERROR;
		resp.Append((void*)&rh, sizeof(ResponseHeader));
		cm.FailMember((char*)m_bHost);
	}

	prh = (ResponseHeader*)resp;

	return rh.response;
}

////////////////////////////////////////////////////
//////  Testing multi threaded acquire and release  ////////////////////////
//////////////////////////////////////////////////

#ifdef ___DEBUG

typedef void (threadproc_t)(int);

class ClientThread {
private:
	std::thread    mythread;
public:
	explicit ClientThread(threadproc_t p, int id = 0) {
		try {
			mythread = std::thread(p, id);
		}
		catch (std::exception& e) {
			exit(-1);
		}
	};
	virtual ~ClientThread() {
		mythread.join();
	}

	std::thread::native_handle_type GetNativeHandle() {
		return mythread.native_handle();
	}
};

mutex aMutex;
bool running = true;
bool ready = false;
int finished = 0;
//int counts[NUM_WORKER_THREADS];
unique_ptr<int[]> counts;
static Buffer       PasswordBuffer;
extern Buffer* pPasswordBuffer;
//std::unique_ptr<ClientThread> workerQ[NUM_WORKER_THREADS];
unique_ptr<std::unique_ptr<ClientThread>[]> workerQ;
int NumThreads = 0;

bool Stopped = false;


void monitorQueue(int id)
{
	while (!ready) {
		std::this_thread::yield();
	}

	while (running) {
		std::unique_lock<std::mutex> mlock(aMutex);
		for (int i = 0; i < NumThreads; i++)
			printf("%d :", counts[i]);
		printf("\r");
	}

	while (finished < NumThreads) {
		std::this_thread::yield();
	}
	finished++;
}

void
NewDoc(TLSClientContext& tlc)
{
	int             rc = -1;
	Buffer CommandResponse;
	CommandHeader ch;
	Buffer cmd;
	ch.command = CMD_GET_MLS_MCS_AES_ENC_KEY;
	ch.szData = 0;
	cmd.Append((void*)&ch, sizeof(ch));
	if (tlc.ExecuteCommand(cmd, CommandResponse)) {
		ResponseHeader* rh = (ResponseHeader*)CommandResponse;
		int len = rh->szData;
		if (rh->response == RSP_SUCCESS) {
			Buffer bPlain;
			uint8_t* pChar = (uint8_t*)CommandResponse + sizeof(ResponseHeader);
			AuthorizationResponse* pAR;
			if (tlc.AES_Decrypt(pChar, len, bPlain) > 0) {
				pAR = (AuthorizationResponse*)bPlain;
				//string s = printAR(pAR);
				//printf("\nresp = %d\nsize = %d\n%s\n", rh->response, rh->szData, s.c_str());
			}
			tlc.EndConnection();
		}
		else {
			//printf("response != RSP_SUCCESS\n");
		}
	}
	else {
		//printf("failed to execute\n");
	}
}

int doClient()
{
	int   r = -1;
	TLSClientContext tlc;
	Buffer bTmp = PasswordBuffer;
	if (tlc.DoClientNoCert(bTmp)) {
		NewDoc(tlc);
		return 0;
	}
	return r;
}

void workerQueue(int id)
{
	while (!ready) {
		std::this_thread::yield();
	}

	while (running) {
		if (doClient() == -1) {
			break;
		}
		counts[id] += 1;
	}
	finished++;
}

void TLSClientContext::Test(int numThreads)
{
	int c;
	ClientThread m(monitorQueue);

	NumThreads = numThreads;

	shared_ptr<MemoryPoolManager> pMPM = MemoryPoolManager::GetInstance();

	pPasswordBuffer = &PasswordBuffer;
	PasswordBuffer.Clear();
	if (!doTlsClientPassword(PasswordBuffer)) {
		return;
	}

	workerQ = std::make_unique<std::unique_ptr<ClientThread>[]>(NumThreads);
	counts = std::make_unique<int[]>(NumThreads);

	for (int i = 0; i < NumThreads; i++) {
		counts[i] = 0;
		workerQ[i] = std::make_unique<ClientThread>(workerQueue, i);
	}

	printf("Press any key to terminate:\n");

	ready = true;

	std::this_thread::yield();

	c = getc(stdin);
	running = false;

	while (finished < (NumThreads + 1)) {
		std::this_thread::yield();
	}
}
#endif

