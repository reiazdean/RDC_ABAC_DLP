/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include "Utils.h"
#include "threadPool.h"
#include "MyLdap.h"
#include "NdacConfig.h"
#include "MyKeyManager.h"
#include "Authorization.h"
#include "LocalServer.h"
#include "TLSServerContext.h"
#include "DocHandler.h"
#include "rdc_events.h"
#include "crlManager.h"
#include "KSPkey.h"
#include "SnmpTrap.h"
#include "clusterServiceManager.h"

using namespace ReiazDean;

#define NUM_ACCEPTING_THREADS 20

void
ServiceReportEvent(
    LPTSTR szMessage,
    WORD dwCategory,
    WORD dwType,
    DWORD dwErr);

extern Buffer* pPasswordBuffer;
vector<SOCKET> TLSServerContext::s_ConectingSockets;
bool TLSServerContext::s_Reserved = false;

SSL_CTX* TLSServerContext::CreateContext()
{
    const    SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx) {
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

        if (!SSL_CTX_set_ciphersuites(ctx,
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256")) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (!SSL_CTX_set_cipher_list(ctx,
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-GCM-SHA256")) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

    }
    
    return ctx;
}

void TLSServerContext::DeleteContext()
{
    if (s_ctx)
    {
        SSL_CTX_free(s_ctx);
        s_ctx = nullptr;
    }
}

/******************************************************************************************
Constructor			TLSServerContext(char* hostname, int port)
Parameters:			(char* hostname, int port)

Description:		Construct an instance with specified inputs

*******************************************************************************************/
TLSServerContext::TLSServerContext()
{
    m_Issuer = nullptr;
    m_Subject = nullptr;
    m_IsNodeSecretValid = false;
}

TLSServerContext::TLSServerContext(SOCKET sock) : TLSContext()
{
    m_sock = sock;
    RAND_bytes(m_nonce, sizeof(m_nonce));
    //memset(m_nonce, 'A', sizeof(m_nonce));
    m_Issuer = nullptr;
    m_Subject = nullptr;
    m_IsNodeSecretValid = false;
    m_NodeNameOrIP.Append((char*)"Invalid", 8);
}

/******************************************************************************************
Destructor			~TLSServerContext()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
TLSServerContext::~TLSServerContext()
{
#ifdef _DEBUG
    printf("TLSServerContext::~TLSServerContext()\n");
#endif
}

bool TLSServerContext::DoTlsServer(SOCKET sock, Buffer& bPwd)
{
    Buffer   bServerCert;
    Buffer   bServerPK;
    Buffer   bCAcert;

    NdacServerConfig& pConf = NdacServerConfig::GetInstance();

    bServerCert = pConf.GetValue(TLS_CERTIFICATE_FILE);
    bServerPK = pConf.GetValue(TLS_PRIV_KEY_FILE);
    bCAcert = pConf.GetValue(TRUSTED_CA_FILE);

    s_PrivateKeyPassword = bPwd;
    s_PrivateKeyPassword.LockPages();
    pPasswordBuffer = &s_PrivateKeyPassword;

    if (!s_ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Drop back to OpenSSL 3.1-style policy
    //SSL_CTX_set_security_level(s_ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(s_ctx, (char*)bServerCert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_default_passwd_cb(s_ctx, (pem_password_cb*)my_cb);

    if (SSL_CTX_use_PrivateKey_file(s_ctx, (char*)bServerPK, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //don't request a client cert during the TLS setup
    //post setup, the client will sign a nonce with the smartcard private key
    SSL_CTX_set_verify(s_ctx, SSL_VERIFY_NONE, 0);

    if (!(SSL_CTX_load_verify_locations(s_ctx, (char*)bCAcert, 0)))
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify_depth(s_ctx, 1);

    //listen for clients
    ServerListen(sock);

    return true;
}

void TLSServerContext::ServerListen(SOCKET sock)
{
    struct sockaddr_in  address;

#ifdef OS_LINUX
    socklen_t addrLen = (socklen_t)sizeof(struct sockaddr_in);
#else
    int addrLen = (int)sizeof(struct sockaddr_in);
#endif

    for (int i = 0; i < NUM_ACCEPTING_THREADS; i++) {
        threadPool::queueThread((void*)TLSServerContext::ServerAccept, 0);
    }

    listen(sock, 10);
    SetToNotBlock(sock);
    LocalServer::WorkerListen();
    while (LocalServer::HasNotStopped())
    {
        int r = -1;
        SOCKET conn = 0;
        r = Select(sock, 0, 500000, true);
        if (r == 0) {
            continue;
        }

        conn = accept(sock, (struct sockaddr*)&address, &addrLen);
        if (conn) {
            std::unique_lock<std::mutex> mlock(s_MutexVar);
            s_ConectingSockets.push_back(conn);
            s_ConditionVar.notify_all();
        }
    }

    CloseSocket(sock);
    LocalServer::DoneWorking();

    return;

}

void* TLSServerContext::ServerAccept(void* args)
{
    LocalServer::WorkerListen();
    while (LocalServer::HasNotStopped()) {
        SOCKET newClientFD = 0;
        {
            std::unique_lock<std::mutex> mlock(s_MutexVar);
            while (LocalServer::HasNotStopped()) {
                if (s_ConectingSockets.size() > 0) {
                    newClientFD = s_ConectingSockets.back();
                    s_ConectingSockets.pop_back();
                    break;
                }
                else
                {
                    s_ConditionVar.wait_for(mlock, std::chrono::seconds(1));
                }
            }
        }

        if (newClientFD) {
            TLSServerContext tls(newClientFD);
            if (tls.StartSSL()) {
                tls.ReadWrite();
            }
        }
    }
    LocalServer::DoneWorking();
    return 0;
}

bool TLSServerContext::StartSSL()
{
    int r = -1;
    int err = SSL_ERROR_WANT_READ;
    int tries = 0;

    {
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        m_ssl = SSL_new(s_ctx);
    }
    
    if (m_ssl) {
        SSL_set_fd(m_ssl, (int)m_sock);
        SetToNotBlock(m_sock);
        r = Select(m_sock, 10, 0, true);//prevent DoS
        if (r > 0) {
            while ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) && tries < MAX_WANT_TRIES) {
                r = SSL_accept(m_ssl);
                err = SSL_get_error(m_ssl, r);
                if (r <= 0) {
                    Select(m_sock, 1, 0, true);
                }
                tries++;
            }
            if (r > 0) {
                return true;
            }
        }
    }

    return false;
}

bool TLSServerContext::ReadWrite()
{
    int r = -1;
    
    DetermineNodeNameOrIP(m_sock, false);
    while (LocalServer::HasNotStopped()) {
        Buffer    b;
        r = Select(m_sock, 1, 0, true);
        if (r == 0) {//timeout triggered
            continue;
        }
        else if (r < 0) {//client ended
            return false;
        }
        else {
            ResponseHeader* rh = nullptr;

            if (DoNonBlockingRead(b) < sizeof(CommandHeader)) {
                return false;
            }
            else if (b.Size() < sizeof(CommandHeader)) {
                return false;
            }
            else {
                CommandHeader* pch = (CommandHeader*)b;
                if (b.Size() != (sizeof(CommandHeader) + pch->szData)) {
                    return false;
                }
            }

            ProcessCommand(b);
            if (DoNonBlockingWrite(b) != b.Size()) {
                return false;
            }
            rh = (ResponseHeader*)b;
            if (rh->response != RSP_SUCCESS) {
                return false;
            }
        }
    }

    return true;
}

void TLSServerContext::DetermineNodeNameOrIP(SOCKET sock, bool bUseDNS)
{
    int port;
    char ipstr[INET6_ADDRSTRLEN];
    char host[NI_MAXHOST];
    socklen_t len;
    int s;
    struct sockaddr_storage addr;

    std::unique_lock<std::mutex> mlock(s_MutexVar);

    len = sizeof addr;
    getpeername(sock, (struct sockaddr*)&addr, &len);
    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in* s = (struct sockaddr_in*)&addr;
        port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    }
    else { // AF_INET6
        struct sockaddr_in6* s = (struct sockaddr_in6*)&addr;
        port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }

    m_NodeNameOrIP.Clear();
    if (bUseDNS) {
        s = getnameinfo((struct sockaddr*)&addr, len, host, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
        if (s == 0) {
            m_NodeNameOrIP.Append(host, strlen(host) + 1);
        }
        else {
            m_NodeNameOrIP.Append(ipstr, strlen(ipstr) + 1);
        }
    }
    else {
        m_NodeNameOrIP.Append(ipstr, strlen(ipstr) + 1);
    }

    m_NodeNameOrIP.NullTerminate();
}

bool TLSServerContext::SendErrorResponse(ReiazDean::Responses resp, Buffer& bRecvSend)
{
    ResponseHeader        respH = { RSP_INTERNAL_ERROR, 0 };

    respH.response = resp;
    respH.szData = 0;
    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));

    return true;
}

bool TLSServerContext::ProcessCommand(Buffer& bRecvSend)
{
    try {
        if (ProcessCommandEx(bRecvSend)) {
            if (bRecvSend.Size() >= sizeof(ResponseHeader)) {
                return true;
            }
        }
        return SendErrorResponse(RSP_INTERNAL_ERROR, bRecvSend);
    }
    catch (...) {
        return SendErrorResponse(RSP_INTERNAL_ERROR, bRecvSend);
    }
}

bool TLSServerContext::ProcessCommandEx(Buffer& bRecvSend)
{
    Mandatory_AC userMac;
    CommandHeader* ch = nullptr;
    CLdap& pCLdap = CLdap::GetInstance();

    if (bRecvSend.Size() < sizeof(CommandHeader)) {
        return SendErrorResponse(RSP_INTERNAL_ERROR, bRecvSend);
    }

    memset(&userMac, 0, sizeof(Mandatory_AC));
    userMac.mls_level = 0xFF;

    ch = (CommandHeader*)bRecvSend;
    if (!ch) {
        return SendErrorResponse(RSP_INTERNAL_ERROR, bRecvSend);
    }

    if (ch->command == Commands::CMD_UPLOAD_CERT_REQUEST) {
        return ReceiveUserCertRequest(bRecvSend);
    }
    else if (ch->command == Commands::CMD_DOWNLOAD_CERTIFICATE) {
        return SendUserCertificate(bRecvSend);
    }
    else if (ch->command == Commands::CMD_SEND_NODE_SECRET) {
        return VerifyClientSignature(bRecvSend);
    }
    else if (ch->command == Commands::CMD_EXCHANGE_KYBER_KEYS) {
        return ExchangeKyber(bRecvSend);
    }
    else if (ch->command == Commands::CMD_GET_SERVER_NONCE) {
        return SendNonce(bRecvSend);
    }
    else if (ch->command == Commands::CMD_GET_CLIENT_SANDBOX_STATE) {
        return SendSandboxState(bRecvSend);
    }
    else if (ch->command == Commands::CMD_GET_CLIENT_SANDBOX_SCRIPT) {
        return SendSandboxScript(bRecvSend);
    }
    else if (ch->command == Commands::CMD_EXCHANGE_SECRETS) {
        return SendSecrets(bRecvSend);
    }
    else if (ch->command == Commands::CMD_EXCHANGE_CLUSTER_MBRS) {
        return SendClusterMembers(bRecvSend);
    }
    else if (ch->command == Commands::CMD_TIMESTAMP_SIGN) {
        return SendTimeStampSign(bRecvSend);
    }

    if (!pCLdap.GetAccessControlForUser(m_UPN, userMac)) {
        return SendErrorResponse(RSP_INTERNAL_ERROR, bRecvSend);
    }

    if (userMac.mls_level > MAX_MLS_LEVEL) {
        return SendErrorResponse(RSP_NOT_AUTHORIZED, bRecvSend);
    }

    PrintStatus((char*)"Connection established");

    //now check for enc/dec requests
    if ((ch->command == Commands::CMD_GET_MLS_MCS_AES_DEC_KEY) && (ch->szData == sizeof(AuthorizationRequest))) {
        PrintStatus((char*)"SendDecryptionKey");
        return SendDecryptionKey(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_GET_MLS_MCS_AES_ENC_KEY) {
        PrintStatus((char*)"SendEncryptionKey");
        return SendEncryptionKey(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_UPLOAD_DOCUMENT) {
        PrintStatus((char*)"Upload document");
        return SaveClassifiedDocument(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_DOWNLOAD_DOCUMENT) {
        PrintStatus((char*)"Download document");
        return SendClassifiedDocument(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_DOWNLOAD_DECLASSIFIED) {
        PrintStatus((char*)"Download declassified document");
        return SendDeclassifiedDocument(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_DOWNLOAD_SW_INSTALLER) {
        return SendSwInstaller(bRecvSend);
    }
    else if (ch->command == Commands::CMD_VERIFY_DOCUMENT) {
        PrintStatus((char*)"VerifyClassifiedDocument");
        return VerifyClassifiedDocument(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_PUBLISH_DOCUMENT) {
        PrintStatus((char*)"PublishClassifiedDocument");
        return PublishClassifiedDocument(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_DECLASSIFY_DOCUMENT) {
        PrintStatus((char*)"DeclassifyClassifiedDocument");
        return DeclassifyClassifiedDocument(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_GET_DOCUMENT_TREE) {
        PrintStatus((char*)"SendDocumentTree");
        return SendDocumentTree(userMac, bRecvSend);
    }
    else if (ch->command == Commands::CMD_GET_DOCUMENT_NAMES) {
        PrintStatus((char*)"SendDocumentNames");
        return SendDocumentNames(userMac, bRecvSend);
    }
    else {
        return SendErrorResponse(RSP_INVALID_COMMAND, bRecvSend);
    }

    return false;
}

bool TLSServerContext::ParseClientCertAndSig(uint8_t* pcASN)
{
    bool       bRc = false;
    uint8_t* pcTemp = pcASN;
    uint32_t   len = 0;
    uint32_t   lenOfLen = 0;
    int        ch;
    Buffer     caCertBundle;
    NdacServerConfig& nc = NdacServerConfig::GetInstance();

    if (!pcTemp) {
        return false;
    }

    ch = pcTemp[0];
    if (ch != CONSTRUCTED_SEQUENCE) {//must be a constructed sequence
        return false;
    }
    pcTemp++;

    len = ReadMemoryEncodedLength(pcTemp, lenOfLen);//the sequence length
    pcTemp += lenOfLen;
    ch = pcTemp[0];
    if (ch != UNIVERSAL_TYPE_OCTETSTR) {//must be a constructed sequence
        return false;
    }
    pcTemp++;

    lenOfLen = 0;
    len = ReadMemoryEncodedLength(pcTemp, lenOfLen);//the sequence length
    pcTemp += lenOfLen;
    m_ClientDerCert.Clear();
    m_ClientDerCert.Append(pcTemp, len);

    pcTemp += len;
    ch = pcTemp[0];
    if (ch != UNIVERSAL_TYPE_OCTETSTR) {//must be a constructed sequence
        return false;
    }
    pcTemp++;

    lenOfLen = 0;
    len = ReadMemoryEncodedLength(pcTemp, lenOfLen);//the sequence length
    pcTemp += lenOfLen;
    m_ClientSignature.Clear();
    m_ClientSignature.Append(pcTemp, len);

    caCertBundle.Clear();
    caCertBundle = nc.GetValue(TRUSTED_CA_FILE);
    if (TLSContext::VerifyCertWithBundle((char*)caCertBundle, (uint8_t*)m_ClientDerCert, m_ClientDerCert.Size())) {
        bRc = true;
    }

    return bRc;
}

bool TLSServerContext::ReadClientAttributes()
{
    bool   bRc = false;
    Certificate c(m_ClientDerCert);
    
    m_ClientCertificate = c;

    m_UPN.Clear();
    if (m_ClientCertificate.GetUPNSubjectAltName(m_UPN)) {
        m_UPN.NullTerminate();
        bRc = true;
    }

    return bRc;
}

bool TLSServerContext::VerifyClientSignature(Buffer& bRecvSend)
{
    bool bRc = true;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;

    m_IsNodeSecretValid = false;

    if (bRecvSend.Size() >= sizeof(CommandHeader)) {
        ch = (CommandHeader*)bRecvSend;
        if (bRecvSend.Size() == (sizeof(CommandHeader) + ch->szData)) {
            pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        }
    }
  
    if (pChar) {
        if (!ParseClientCertAndSig(pChar)) {
            //printf("ParseClientCertAndSig  invalid!\n");
            respH.response = RSP_CERT_INVALID;
            bRc = false;
        }

        if (bRc && !ReadClientAttributes()) {
            respH.response = RSP_NOT_VALID_NODE;
            bRc = false;
        }

        if (bRc) {
            uint8_t* pDer = (uint8_t*)m_ClientDerCert;
            Buffer b;
            Buffer bHash;
            
            b.Append(m_nonce, sizeof(m_nonce));

            Sha256((uint8_t*)b, b.Size(), bHash);

            if (RSA_VerifyDER(pDer, m_ClientDerCert.Size(), (uint8_t*)bHash, bHash.Size(), m_ClientSignature, m_ClientSignature.Size())) {
                Certificate cert(m_ClientDerCert);
                //cert.PrintOn(stdout);
                if (!cert.IsValid()) {
                    //printf("Cert dates invalid!\n");
                    respH.response = RSP_CERT_INVALID;
                }
                else if (CRLManager::IsCertificateRevoked(m_ClientDerCert)) {
                    //printf("Cert revoked!\n");
                    respH.response = RSP_CERT_REVOKED;
                }
                else {
                    m_IsNodeSecretValid = true;
                    respH.response = RSP_SUCCESS;
                }
            }
            else {
                respH.response = RSP_SIGNATURE_INVALID;
            }
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));

    return true;
}

bool TLSServerContext::ExchangeKyber(Buffer& bRecvSend)
{
    Buffer bWrappedAESKey;
    bool bRc = false;
    ResponseHeader respH = { RSP_INTERNAL_ERROR, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;

    if (bRecvSend.Size() >= sizeof(CommandHeader)) {
        ch = (CommandHeader*)bRecvSend;
        if (bRecvSend.Size() == (sizeof(CommandHeader) + ch->szData)) {
            pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        }
    }

    if (pChar) {
        if (m_KyberKeyPair.WrapRandomAESkey(pChar, ch->szData, bWrappedAESKey) > 0) {
            Buffer bSig;
            bWrappedAESKey.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            s_DilithiumKeyPair.Sign(bWrappedAESKey, bSig);
#ifdef _DEBUG
            printf("\nverify = %s\n", s_DilithiumKeyPair.Verify(bWrappedAESKey, bSig) ? "SUCCESS" : "FAILED");
#endif
            bSig.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bWrappedAESKey.Append(bSig);
            bWrappedAESKey.ASN1Wrap(CONSTRUCTED_SEQUENCE);

            respH.response = RSP_SUCCESS;
            respH.szData = bWrappedAESKey.Size();

            bRecvSend.Clear();
            bRecvSend.Append((void*)&respH, sizeof(respH));
            bRecvSend.Append(bWrappedAESKey);

            return true;
        }
    }

    return false;
}

bool TLSServerContext::SendNonce(Buffer& bRecvSend)
{
    bool bRc = false;
    ResponseHeader respH = { RSP_INTERNAL_ERROR, 0 };
    
    respH.response = RSP_SUCCESS;
    respH.szData = sizeof(m_nonce);

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    bRecvSend.Append(m_nonce, sizeof(m_nonce));

    return true;
}

bool TLSServerContext::SendSandboxState(Buffer& bRecvSend)
{
    bool             bRc = false;
    ResponseHeader   respH = { RSP_INTERNAL_ERROR, 0 };
    uint8_t cState = 0x1;
    bool bSandboxed = true;
    bool bInDomain = false;
    uint16_t mlsComputer = MAX_MLS_LEVEL * 2;
    
    CLdap& ldp = CLdap::GetInstance();

    DetermineNodeNameOrIP(m_sock, true);
    bInDomain = ldp.IsComputerInDomain((char*)m_NodeNameOrIP, bSandboxed, mlsComputer);
    if (bInDomain && !bSandboxed) {
        cState = 0x0;
    }
   
#ifdef _DEBUG
    printf("FQDN = %s  INDOM = %d  SANDBOXED = %d  MLS = %u", (char*)m_NodeNameOrIP, bInDomain, bSandboxed, mlsComputer);
#endif

    respH.response = RSP_SUCCESS;
    respH.szData = 1;

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    bRecvSend.Append((void*)&cState, 1);

    return true;
}

bool TLSServerContext::SendSandboxScript(Buffer& bRecvSend)
{
    bool             bRc = false;
    ResponseHeader   respH = { RSP_INTERNAL_ERROR, 0 };
    char script[] =
        "<Configuration>\n\
\t<vGpu>Disable</vGpu>\n\
\t<ClipboardRedirection>Disable</ClipboardRedirection>\n\
\t<PrinterRedirection>Disable</PrinterRedirection>\n\
\t<ProtectedClient>Enable</ProtectedClient>\n\
\t<Networking>Enable</Networking>\n\
\t<MappedFolders>\n\
\t\t<MappedFolder>\n\
\t\t\t<HostFolder>%s\\Documents\\Temp</HostFolder>\n\
\t\t\t<SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Downloads</SandboxFolder>\n\
\t\t\t<ReadOnly>true</ReadOnly>\n\
\t\t</MappedFolder>\n\
\t</MappedFolders>\n\
\t<LogonCommand>\n\
\t\t<Command>C:\\users\\WDAGUtilityAccount\\Downloads\\acstartup.cmd</Command>\n\
\t</LogonCommand>\n\
</Configuration>\n";

    respH.response = RSP_SUCCESS;
    respH.szData = (uint32_t)strlen(script);

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    bRecvSend.Append((void*)script, strlen(script));

    return true;
}

bool TLSServerContext::ProtectPassword()
{
    return true;
}

bool TLSServerContext::GetCertPassword(Buffer& bPwd)
{
    Buffer bDec;
    int32_t   len = s_PrivateKeyPassword.Size();
    if (s_ECKeyPair.AES_Decrypt((uint8_t*)s_PrivateKeyPassword, len, bDec) > 0) {
        bPwd = bDec;
        return true;
    }
    return false;
}

bool TLSServerContext::SendSecrets(Buffer& bRecvSend)
{
    int8_t bMsg[256];
    bool bRc = false;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    Buffer bEnc;
    int32_t len = 0;
    ClusterServiceManager& csm = ClusterServiceManager::GetInstance();
    Buffer bSecrets = csm.GetSecrets();

    if (bSecrets.Size() > 0) {
        if (m_KyberKeyPair.AES_Encrypt((uint8_t*)bSecrets, bSecrets.Size(), bEnc) > 0) {
            respH.szData = bEnc.Size();
            respH.response = RSP_SUCCESS;
        }
        else {
            respH.szData = 0;
            respH.response = RSP_INTERNAL_ERROR;
        }
        bRc = true;
    }

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"Cluster member was %s secrets!", ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"));
            return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (respH.response == RSP_SUCCESS) {
        bRecvSend.Append(bEnc);
    }

    return true;
}

bool TLSServerContext::SendClusterMembers(Buffer& bRecvSend)
{
    bool bRc = false;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    Buffer bEnc;
    int32_t len = 0;
    Buffer bMbrs;
    ClusterServiceManager& csm = ClusterServiceManager::GetInstance();

    csm.ReadMemberFile(bMbrs);
    if (bMbrs.Size() > 0) {
        respH.szData = bMbrs.Size();
        respH.response = RSP_SUCCESS;
        bRc = true;
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (respH.response == RSP_SUCCESS) {
        bRecvSend.Append(bMbrs);
    }

    return true;
}

bool TLSServerContext::SendTimeStampSign(Buffer& bRecvSend)
{
    bool bRc = false;
    ResponseHeader respH = { RSP_MEMORY_ERROR, 0 };
    CommandHeader* ch = (CommandHeader*)bRecvSend;
    uint8_t* pChar = nullptr;
    Buffer bData;
    Buffer bSig;
    Buffer bTSsig;
    if (ch->szData > 0) {
        if (bRecvSend.Size() == (sizeof(CommandHeader) + ch->szData)) {
            Buffer bNow;
            time_t now;
            Buffer bHash;
            pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
            bData.Append((void*)pChar, ch->szData);
            time(&now);
            bNow.Append((void*)&now, sizeof(time_t));
            bNow.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bData.Append((void*)bNow, bNow.Size());
            if (s_DilithiumKeyPair.Sign(bData, bSig) > 0) {
                bSig.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
                bTSsig = bNow;
                bTSsig.Append(bSig);
                bTSsig.ASN1Wrap(CONSTRUCTED_SEQUENCE);
                respH.response = RSP_SUCCESS;
                respH.szData = bTSsig.Size();
            }
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (respH.response == RSP_SUCCESS) {
        bRecvSend.Append(bTSsig);
    }

    return true;
}

bool TLSServerContext::SendEncryptionKey(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    int8_t bMsg[256];
    bool bRc = false;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    AuthorizationResponse ar;
    Authorization auth;
    Buffer bEnc;
    int32_t len = 0;

    if (m_IsNodeSecretValid) {
        respH.response = auth.GetEncryptionKeyForUser(userMac, ar);
        if (respH.response == RSP_SUCCESS) {
            len = sizeof(AuthorizationResponse);
            if (m_KyberKeyPair.AES_Encrypt((uint8_t*)&ar, len, bEnc) > 0) {
                respH.szData = bEnc.Size();
            }
            else {
                respH.szData = 0;
                respH.response = RSP_INTERNAL_ERROR;
            }
        }
        bRc = true;
    }

    memset(&ar, 0, sizeof(AuthorizationResponse));

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s an encryption key!", (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"));
            return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (respH.response == RSP_SUCCESS) {
        bRecvSend.Append(bEnc);
    }

    return true;
}

bool TLSServerContext::SendDecryptionKey(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    int8_t bMsg[256];
    bool bRc = false;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationResponse ar;
    Authorization auth;
    AuthorizationRequest* pAR = nullptr;
    Buffer bEnc;
    int32_t len = 0;

    if (bRecvSend.Size() == (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    if (m_IsNodeSecretValid && pAR) {
        respH.response = auth.GetDecryptionKeyForUser(userMac, pAR, ar);
        if (respH.response == RSP_SUCCESS) {
            len = sizeof(AuthorizationResponse);
            if (m_KyberKeyPair.AES_Encrypt((uint8_t*)&ar, len, bEnc) > 0) {
                respH.szData = bEnc.Size();
            }
            else {
                respH.szData = 0;
                respH.response = RSP_INTERNAL_ERROR;
            }
        }
        bRc = true;
    }

    memset(&ar, 0, sizeof(AuthorizationResponse));

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s a decryption key!", (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"));
            return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (respH.response == RSP_SUCCESS) {
        bRecvSend.Append(bEnc);
    }

    return true;
}

bool TLSServerContext::SendDocumentTree(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    bool bRc = false;
    Buffer bTree;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    NdacServerConfig& nc = NdacServerConfig::GetInstance();

    bool bSandboxed = true;
    bool bInDomain = false;
    uint16_t mlsComputer = MAX_MLS_LEVEL * 2;

    CLdap& ldp = CLdap::GetInstance();
    DetermineNodeNameOrIP(m_sock, true);
    bInDomain = ldp.IsComputerInDomain((char*)m_NodeNameOrIP, bSandboxed, mlsComputer);

    respH.szData = 0;
    if (!bInDomain) {
        int8_t bMsg[256];
        stringWrite(bMsg, sizeof(bMsg), (int8_t*)"Non domain computer %s was denied file access permissions!", (char*)m_NodeNameOrIP);
        SnmpTrap trap((char*)bMsg, (uint32_t)strlen((char*)bMsg));
        respH.response = RSP_NOT_VALID_NODE;
        bRc = true;
    }
    else if (!m_IsNodeSecretValid) {
        respH.response = RSP_SIGNATURE_INVALID;
    }
    else {
        Buffer bRoot16;
        wchar_t start[16] = L"<DIR>\n";
        size_t szStart = 0;
        wchar_t end[16] = L"</DIR>\n";
        size_t szEnd = 0;

        if (SUCCEEDED(StringCbLengthW(start, 32, &szStart)) &&
            SUCCEEDED(StringCbLengthW(end, 32, &szEnd))) {
            Buffer bRoot = nc.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
            if (GetWcharFromUtf8((char*)bRoot, bRoot16)) {
                try {
                    bTree.Append((void*)start, szStart);
                    bTree.Append((void*)bRoot16, bRoot16.Size() - sizeof(wchar_t));
                    bTree.Append((void*)L"\n", sizeof(wchar_t));
                    GetFilteredDirectoryTree((wchar_t*)bRoot16, bTree, userMac, 1);
                    bTree.Append((void*)end, szEnd);
                    bTree.NullTerminate();
                    bTree.NullTerminate();
                    respH.szData = bTree.Size();
                    respH.response = RSP_SUCCESS;
                    bRc = true;
                }
                catch (...) {
                    bTree.Clear();
                    respH.response = RSP_MEMORY_ERROR;
                    bRc = false;
                }
            }
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (bRc) {
        bRecvSend.Append(bTree);
    }

    return true;
}

bool TLSServerContext::SendDocumentNames(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    int32_t i = 0;
    ResponseHeader respH = { RSP_SUCCESS, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Buffer bFiles;

    if (bRecvSend.Size() == (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    respH.szData = 0;
    if (pAR) {
        if (!m_IsNodeSecretValid) {
            respH.response = RSP_SIGNATURE_INVALID;
        }
        else {
            if (GetDirectoryContents((wchar_t*)pAR->docMAC.mls_doc_name, bFiles) > 0) {
                respH.szData = bFiles.Size();
            }
            else {
                respH.response = RSP_NO_ITEMS_FOUND;
            }
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (bFiles.Size() > 0) {
        bRecvSend.Append(bFiles);
    }

    return true;
}

bool TLSServerContext::SaveClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    NdacServerConfig& pConf = NdacServerConfig::GetInstance();
    HANDLE hr = INVALID_HANDLE_VALUE;
    int8_t bMsg[256];
    Responses response = RSP_NULL;
    int32_t len = 0;
    wchar_t fname[MAX_NAME];
    wchar_t tempfname[MAX_NAME];
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Buffer bRoot = pConf.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
    bRoot.NullTerminate();

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    if (m_IsNodeSecretValid && pAR) {
        respH.response = RSP_SUCCESS;

        memset(fname, 0, sizeof(fname));
        swprintf_s(fname, MAX_NAME - 1, L"%S\\Drafts\\%S\\%S\\%S",
            (char*)bRoot, userMac.mcs_desc[0], userMac.mls_desc, (char*)m_UPN);

        if (!DirectoryExistsW(fname)) {
            hr = LockFilePath(fname);//lock the file destination parent folder
            if (hr != INVALID_HANDLE_VALUE)
            {
                if (!CreateDirectoryW(fname, 0)) {
                    respH.response = RSP_INTERNAL_ERROR;
                }
                UnlockEntireFile(hr);
                hr = INVALID_HANDLE_VALUE;
            }
            else {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }

        }


        memset(fname, 0, sizeof(fname));
        swprintf_s(fname, MAX_NAME - 1, L"%S\\Drafts\\%S\\%S\\%S\\%s",
            (char*)bRoot, userMac.mcs_desc[0], userMac.mls_desc, (char*)m_UPN, (wchar_t*)pAR->docMAC.mls_doc_name);//TEST THIS ASAP!!!!!!!!!!!!!!!!!
        if (wcslen(fname) >= MAX_PATH) {
            respH.response = RSP_MAX_PATH_EXCEEDED;
        }
        else {
            Buffer bTmpFN;
            uint8_t nonce[16];
            RAND_bytes(nonce, sizeof(nonce));
            hexEncode(nonce, sizeof(nonce), bTmpFN);
            bTmpFN.NullTerminate();

            memset(tempfname, 0, sizeof(tempfname));
            swprintf_s(tempfname, MAX_NAME - 1, L"%S\\Temp\\%S",
                (char*)bRoot, (char*)bTmpFN);
            len = pAR->docMAC.mls_doc_size;
        }

        if (respH.response == RSP_SUCCESS) {
            hr = LockFilePath(fname);//lock the file destination folder
            if (hr == INVALID_HANDLE_VALUE) {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }
            //send to client
            bRecvSend.Clear();
            bRecvSend.Append((void*)&respH, sizeof(respH));
            if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
                if (respH.response == RSP_SUCCESS) {
                    response = DocHandler::ReceiveDocument(*this, fname, tempfname, len, 0);
                }
            }
            if (hr != INVALID_HANDLE_VALUE) {
                UnlockEntireFile(hr);
            }
        }

        if (response == RSP_NULL) {
            respH.szData = 0;
            respH.response = response;
        }

        ServiceReportEvent(
            [&]() mutable {
                stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s upload and save permissions for \"%S\"!",
                    (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"), (wchar_t*)fname);
                return (char*)bMsg;
            }(),
                COMMUNICATION_CATEGORY,
                ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
                ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));
    }

    return true;
}

bool TLSServerContext::SendSwInstaller(Buffer& bRecvSend)
{
    wchar_t fname[MAX_NAME];
    ResponseHeader respH = { RSP_FILE_ERROR, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    DocHandler dh;

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }
    
    if (m_IsNodeSecretValid && pAR) {
        respH.szData = 0;
        memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
        if (!dh.OpenUnprotectedDocument(fname, true)) {
            respH.response = RSP_FILE_ERROR;
        }
        else {
            struct _stat     buf;
            if (_wstat(fname, &buf) == 0) {
                respH.szData = buf.st_size;
                respH.response = RSP_SUCCESS;
            }
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
        if (respH.response == RSP_SUCCESS) {
            respH.response = dh.SendDocument(*this);
        }
    }

    return true;
}

bool TLSServerContext::SendClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    int8_t bMsg[256];
    wchar_t fname[MAX_NAME];
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Authorization auth;
    DocHandler dh;

    bool bSandboxed = true;
    bool bInDomain = false;
    uint16_t mlsComputer = MAX_MLS_LEVEL * 2;

    CLdap& ldp = CLdap::GetInstance();
    DetermineNodeNameOrIP(m_sock, true);
    bInDomain = ldp.IsComputerInDomain((char*)m_NodeNameOrIP, bSandboxed, mlsComputer);

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    if (m_IsNodeSecretValid && pAR) {
        respH.szData = 0;
        memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
        if (!dh.OpenDocument(fname, true)) {
            if (dh.GetLockHandle() == INVALID_HANDLE_VALUE) {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }
            else {
                respH.response = RSP_FILE_ERROR;
            }
        }
        else {
            struct _stat     buf;
            if (_wstat(fname, &buf) == 0) {
                respH.szData = buf.st_size;
                respH.response = auth.CanDownlaod(userMac, dh, mlsComputer);
            }
        }
        
        if (respH.response == RSP_HOST_MLS_UNAUTHORIZED) {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was denied download permissions to \"%S\" because of insufficient MLS privileges!",
                (char*)m_NodeNameOrIP, (wchar_t*)fname);
            SnmpTrap trap((char*)bMsg, (uint32_t)strlen((char*)bMsg));
        }
    }

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s download permissions to \"%S\"!",
                       (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"), (wchar_t*)fname);
            return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
        if (respH.response == RSP_SUCCESS) {
            respH.response = dh.SendDocument(*this);
        }
    }

    return true;
}

bool TLSServerContext::SendDeclassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    int8_t bMsg[256];
    wchar_t fname[MAX_NAME];
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Authorization auth;
    DocHandler dh;

    bool bSandboxed = true;
    bool bInDomain = false;
    uint16_t mlsComputer = MAX_MLS_LEVEL * 2;

    CLdap& ldp = CLdap::GetInstance();
    DetermineNodeNameOrIP(m_sock, true);
    bInDomain = ldp.IsComputerInDomain((char*)m_NodeNameOrIP, bSandboxed, mlsComputer);

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    if (m_IsNodeSecretValid && pAR) {
        respH.szData = 0;
        memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
        if (!dh.OpenUnprotectedDocument(fname, true)) {
            if (dh.GetLockHandle() == INVALID_HANDLE_VALUE) {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }
            else {
                respH.response = RSP_FILE_ERROR;
            }
        }
        else {
            struct _stat     buf;
            if (_wstat(fname, &buf) == 0) {
                respH.szData = buf.st_size;
                respH.response = RSP_SUCCESS;
            }
        }
    }

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s download permissions to \"%S\"!",
                (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"), (wchar_t*)fname);
            return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
        if (respH.response == RSP_SUCCESS) {
            respH.response = dh.SendDocument(*this);
        }
    }

    return true;
}

bool TLSServerContext::PublishClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    HANDLE hr = INVALID_HANDLE_VALUE;
    int8_t bMsg[256];
    wchar_t fname[MAX_NAME];
    wchar_t fnameCopy[MAX_NAME];
    wchar_t folder[MAX_NAME];
    std::vector<wchar_t*> pieces;
    uint32_t count = 0;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Authorization auth;
    NdacServerConfig& pConf = NdacServerConfig::GetInstance();

    Buffer bRoot = pConf.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
    bRoot.NullTerminate();

    bool bSandboxed = true;
    bool bInDomain = false;
    uint16_t mlsComputer = MAX_MLS_LEVEL * 2;

    CLdap& ldp = CLdap::GetInstance();
    DetermineNodeNameOrIP(m_sock, true);
    bInDomain = ldp.IsComputerInDomain((char*)m_NodeNameOrIP, bSandboxed, mlsComputer);

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    if (pAR) {
        memset(fname, 0, sizeof(fname));
        memset(fnameCopy, 0, sizeof(fnameCopy));
        memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
        memcpy(fnameCopy, pAR->docMAC.mls_doc_name, MAX_NAME);

        if (m_IsNodeSecretValid && bInDomain) {
            DocHandler dh;
            respH.szData = 0;

            if (!dh.OpenDocument(fname, true)) {
                if (dh.GetLockHandle() == INVALID_HANDLE_VALUE) {
                    respH.response = RSP_CANNOT_LOCK_FILE;
                }
                else {
                    respH.response = RSP_FILE_ERROR;
                }
            }
            else {
                respH.response = auth.CanPublish(m_UPN, userMac, dh, mlsComputer);
            }
        }
    }

    if (respH.response == RSP_HOST_MLS_UNAUTHORIZED) {
        stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was denied publishing permissions to \"%S\" because of insufficient MLS privileges!",
            (char*)m_NodeNameOrIP, (wchar_t*)fname);
        SnmpTrap trap((char*)bMsg, (uint32_t)strlen((char*)bMsg));
    }

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s publishing permissions to \"%S\"!",
            (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"), (wchar_t*)fname);
    return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    if (respH.response == RSP_SUCCESS) {
        //const wchar_t* fileName = PathFindFileNameW((WCHAR*)fname);
        count = splitStringW(fnameCopy, (wchar_t*)L"\\", pieces);
        if (count < 3) {
            respH.szData = 0;
            respH.response = RSP_INTERNAL_ERROR;
        }
    }

    if (respH.response == RSP_SUCCESS) {
        memset(folder, 0, sizeof(folder));
        swprintf_s(folder, MAX_NAME - 1, L"%S\\Published\\%S\\%S\\%s",
            (char*)bRoot, userMac.mcs_desc[0], userMac.mls_desc, pieces.at(count - 2));

        if (!DirectoryExistsW(folder)) {
            hr = LockFilePath(folder);//lock the file destination parent folder
            if (hr != INVALID_HANDLE_VALUE)
            {
                if (!CreateDirectoryW(folder, 0)) {
                    respH.response = RSP_INTERNAL_ERROR;
                }
                UnlockEntireFile(hr);
                hr = INVALID_HANDLE_VALUE;
            }
            else {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }

        }
    }
    
    if (respH.response == RSP_SUCCESS) {
        memset(folder, 0, sizeof(folder));
        swprintf_s(folder, MAX_NAME - 1, L"%S\\Published\\%S\\%S\\%s\\%s",
            (char*)bRoot, userMac.mcs_desc[0], userMac.mls_desc, pieces.at(count - 2), pieces.at(count - 1));
        
        hr = LockFilePath(folder);
        if (hr != INVALID_HANDLE_VALUE) {
            if (MoveFileW(fname, folder)) {
                respH.response = RSP_SUCCESS;
            }
            else {
                respH.response = RSP_FILE_MOVE_ERROR;
            }
            UnlockEntireFile(hr);
            hr = INVALID_HANDLE_VALUE;
        }
        else {
            respH.response = RSP_CANNOT_LOCK_FILE;
        }
       
        ServiceReportEvent(
            [&]() mutable {
                stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s %s published \"%S\"!",
                (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Successfully" : (char*)"Unsuccessfully"), (wchar_t*)fname);
        return (char*)bMsg;
            }(),
                COMMUNICATION_CATEGORY,
                ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
                ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    
    return true;
}

bool TLSServerContext::DecryptDeclassifiedFile(Mandatory_AC& userMac, wchar_t* pwcFname)
{
    bool bRc = false;
    DocHandler dh;
    AuthorizationRequest areq;
    AuthorizationResponse aresp;
    Authorization auth;

    if (dh.OpenDocument((wchar_t*)pwcFname, false)) {
        if (dh.GetAuthRequest(areq)) {
            if (RSP_SUCCESS == auth.GetDecryptionKeyForUser(userMac, &areq, aresp)) {
                Buffer out((void*)pwcFname, wcslen(pwcFname) * sizeof(WCHAR));
                WCHAR* pwc = wcsstr((WCHAR*)out, L".classified");
                if (pwc) {
                    FILE* fp = 0;
                    pwc[0] = 0;
                    fp = f_open_u((WCHAR*)out, (WCHAR*)L"wb");
                    if (fp) {
                        dh.SetAuthResponse(aresp);
                        bRc = dh.DecryptVerify(fp, nullptr);
                        fclose(fp);
                        
                    }
                }
            }
        }
    }

    return bRc;
}

bool TLSServerContext::DeclassifyClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    HANDLE hr = INVALID_HANDLE_VALUE;
    int8_t bMsg[256];
    wchar_t fname[MAX_NAME];
    wchar_t fnameCopy[MAX_NAME];
    wchar_t folder[MAX_NAME];
    std::vector<wchar_t*> pieces;
    uint32_t count = 0;
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Authorization auth;
    NdacServerConfig& pConf = NdacServerConfig::GetInstance();

    Buffer bRoot = pConf.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
    bRoot.NullTerminate();

    bool bSandboxed = true;
    bool bInDomain = false;
    uint16_t mlsComputer = MAX_MLS_LEVEL * 2;

    CLdap& ldp = CLdap::GetInstance();
    DetermineNodeNameOrIP(m_sock, true);
    bInDomain = ldp.IsComputerInDomain((char*)m_NodeNameOrIP, bSandboxed, mlsComputer);

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    if (pAR) {
        memset(fname, 0, sizeof(fname));
        memset(fnameCopy, 0, sizeof(fnameCopy));
        memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
        memcpy(fnameCopy, pAR->docMAC.mls_doc_name, MAX_NAME);

        if (m_IsNodeSecretValid && bInDomain) {
            DocHandler dh;
            respH.szData = 0;

            if (!dh.OpenDocument(fname, true)) {
                if (dh.GetLockHandle() == INVALID_HANDLE_VALUE) {
                    respH.response = RSP_CANNOT_LOCK_FILE;
                }
                else {
                    respH.response = RSP_FILE_ERROR;
                }
            }
            else {
                respH.response = auth.CanPublish(m_UPN, userMac, dh, mlsComputer);
            }
        }
    }

    if (respH.response == RSP_HOST_MLS_UNAUTHORIZED) {
        stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was denied declassification permissions to \"%S\" because of insufficient MLS privileges!",
            (char*)m_NodeNameOrIP, (wchar_t*)fname);
        SnmpTrap trap((char*)bMsg, (uint32_t)strlen((char*)bMsg));
    }

    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s was %s declassification permissions to \"%S\"!",
                (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Granted" : (char*)"Denied"), (wchar_t*)fname);
            return (char*)bMsg;
        }(),
            COMMUNICATION_CATEGORY,
            ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
            ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));

    if (respH.response == RSP_SUCCESS) {
        //const wchar_t* fileName = PathFindFileNameW((WCHAR*)fname);
        count = splitStringW(fnameCopy, (wchar_t*)L"\\", pieces);
        if (count < 3) {
            respH.szData = 0;
            respH.response = RSP_INTERNAL_ERROR;
        }
    }

    if (respH.response == RSP_SUCCESS) {
        memset(folder, 0, sizeof(folder));
        swprintf_s(folder, MAX_NAME - 1, L"%S\\Declassified\\%S\\%s",
            (char*)bRoot, userMac.mcs_desc[0], pieces.at(count - 2));

        if (!DirectoryExistsW(folder)) {
            hr = LockFilePath(folder);//lock the file destination parent folder
            if (hr != INVALID_HANDLE_VALUE)
            {
                if (!CreateDirectoryW(folder, 0)) {
                    respH.response = RSP_INTERNAL_ERROR;
                }
                UnlockEntireFile(hr);
                hr = INVALID_HANDLE_VALUE;
            }
            else {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }

        }
    }

    if (respH.response == RSP_SUCCESS) {
        memset(folder, 0, sizeof(folder));
        //folder will now contain the full name of the declassified file, path included
        swprintf_s(folder, MAX_NAME - 1, L"%S\\Declassified\\%S\\%s\\%s",
            (char*)bRoot, userMac.mcs_desc[0], pieces.at(count - 2), pieces.at(count - 1));

        hr = LockFilePath(folder);
        if (hr != INVALID_HANDLE_VALUE) {
            if (CopyFileW(fname, folder, FALSE)) {
                if (DecryptDeclassifiedFile(userMac, folder)) {
                    wchar_t renamed[MAX_NAME];
                    memset(renamed, 0, sizeof(renamed));
                    swprintf_s(renamed, MAX_NAME - 1, L"%s.declassified", fname);
                    MoveFileW(fname, renamed);
                }
                DeleteFileW(folder);
            }
            else {
                respH.response = RSP_FILE_MOVE_ERROR;
            }
            UnlockEntireFile(hr);
            hr = INVALID_HANDLE_VALUE;
        }
        else {
            respH.response = RSP_CANNOT_LOCK_FILE;
        }

        ServiceReportEvent(
            [&]() mutable {
                stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s %s declassified \"%S\"!",
                    (char*)m_UPN, ((respH.response == RSP_SUCCESS) ? (char*)"Successfully" : (char*)"Unsuccessfully"), (wchar_t*)fname);
                return (char*)bMsg;
            }(),
                COMMUNICATION_CATEGORY,
                ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_WARNING),
                ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_DENIED));
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));

    return true;
}

bool TLSServerContext::VerifyClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend)
{
    wchar_t fname[MAX_NAME];
    ResponseHeader respH = { RSP_NOT_VALID_NODE, 0 };
    CommandHeader* ch = nullptr;
    uint8_t* pChar = nullptr;
    AuthorizationRequest* pAR = nullptr;
    Authorization auth;
    DocHandler dh;

    if (bRecvSend.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
        ch = (CommandHeader*)bRecvSend;
        pChar = (uint8_t*)bRecvSend + sizeof(CommandHeader);
        pAR = (AuthorizationRequest*)pChar;
    }

    respH.szData = 0;
    if (m_IsNodeSecretValid && pAR) {
        memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
        if (!dh.OpenDocument(fname, true)) {
            if (dh.GetLockHandle() == INVALID_HANDLE_VALUE) {
                respH.response = RSP_CANNOT_LOCK_FILE;
            }
            else {
                respH.response = RSP_FILE_ERROR;
            }
        }
        else if (dh.TimeStampVerify(s_DilithiumKeyPair)) {
            respH.response = RSP_SUCCESS;
        }
        else {
            respH.response = RSP_SIGNATURE_INVALID;
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
        return true;
    }

    return false;
}

bool TLSServerContext::ReceiveUserCertRequest(Buffer& bRecvSend)
{
    int8_t bMsg[256];
    Buffer bData;
    SequenceReaderX seq;
    Buffer bUPN;
    Buffer bCSR;
    ResponseHeader respH = { RSP_FILE_ERROR, 0 };
    CommandHeader* ch = nullptr;
    int8_t* pcData = nullptr;
    NdacServerConfig& pConf = NdacServerConfig::GetInstance();

    if (bRecvSend.Size() >= sizeof(CommandHeader)) {
        ch = (CommandHeader*)bRecvSend;
        if (bRecvSend.Size() == (sizeof(CommandHeader) + ch->szData)) {
            pcData = (int8_t*)bRecvSend + sizeof(CommandHeader);
        }
    }

    if (pcData) {
        bData.Append(pcData, ch->szData);
        seq.Initilaize(bData);

        if (seq.getValueAt(0, bUPN) && seq.getValueAt(1, bCSR)) {
            int8_t fname[MAX_NAME];
            Buffer bRoot = pConf.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
            bRoot.NullTerminate();
            bUPN.NullTerminate();
            bCSR.NullTerminate();
            memset(fname, 0, sizeof(fname));
            stringWrite(fname, MAX_NAME - 1, (int8_t*)"%s\\Temp\\%s.csr", (char*)bRoot, (char*)bUPN);
#ifdef _DEBUG
            printf("%s = \n%s\n", (char*)fname, (char*)bCSR);
#endif
            if (saveToFile((int8_t*)fname, (int8_t*)bCSR, bCSR.Size()) == 1) {
                respH.response = RSP_SUCCESS;
            }

            ServiceReportEvent(
                [&]() mutable {
                    stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s saving certificate request file %s", ((respH.response == RSP_SUCCESS) ? (char*)"Success" : (char*)"Denied"), (char*)fname);
                    return (char*)bMsg;
                }(),
                    COMMUNICATION_CATEGORY,
                    ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_ERROR),
                    ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_FAILED));
        }
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
        return true;
    }

    return false;
}

bool TLSServerContext::SendUserCertificate(Buffer& bRecvSend)
{
    int8_t bMsg[256];
    Buffer bData;
    int8_t fname[MAX_NAME];
    ResponseHeader respH = { RSP_FILE_ERROR, 0 };
    CommandHeader* ch = nullptr;
    int8_t* pcData = nullptr;
    NdacServerConfig& pConf = NdacServerConfig::GetInstance();

    if (bRecvSend.Size() >= sizeof(CommandHeader)) {
        ch = (CommandHeader*)bRecvSend;
        if (bRecvSend.Size() == (sizeof(CommandHeader) + ch->szData)) {
            pcData = (int8_t*)bRecvSend + sizeof(CommandHeader);
        }
    }

    if (pcData) {
        Buffer bRoot = pConf.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
        bRoot.NullTerminate();

        bData.Append(pcData, ch->szData);
        bData.NullTerminate_w();

        memset(fname, 0, sizeof(fname));
        stringWrite(fname, MAX_NAME - 1, (int8_t*)"%s\\Temp\\%S.p7b", (char*)bRoot, (wchar_t*)bData);
#ifdef _DEBUG
        printf("\nCert = %s\n", (char*)fname);
#endif
        bData.Clear();
        if (readFile((char*)fname, bData)) {
            respH.response = RSP_SUCCESS;
            respH.szData = bData.Size();
        }

        ServiceReportEvent(
            [&]() mutable {
                stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s sending user certificate: %s", ((respH.response == RSP_SUCCESS) ? (char*)"Success" : (char*)"Failed"), (char*)fname);
                return (char*)bMsg;
            }(),
                COMMUNICATION_CATEGORY,
                ((respH.response == RSP_SUCCESS) ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_ERROR),
                ((respH.response == RSP_SUCCESS) ? MSG_SUCCESS : MSG_FAILED));
    }

    bRecvSend.Clear();
    bRecvSend.Append((void*)&respH, sizeof(respH));
    if (respH.response == RSP_SUCCESS) {
        bRecvSend.Append(bData);
    }
    if (DoNonBlockingWrite(bRecvSend) == bRecvSend.Size()) {
        return true;
    }

    return false;
}

void TLSServerContext::PrintStatus(char* pcOperation)
{
#ifdef _DEBUG
    char cDate[128] = { 0 };
    char cTime[128] = { 0 };

    GetDateFormat(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, NULL, NULL, cDate, sizeof(cDate));
    GetTimeFormat(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, NULL, NULL, cTime, sizeof(cTime));
    printf("\n%s %s %s requested by %s from %s\n====================================\n",
        cDate,
        cTime,
        pcOperation,
        (char*)m_UPN,
        (char*)m_NodeNameOrIP);
#endif
}


