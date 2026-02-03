/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "Utils.h"
#include "NdacConfig.h"
#include "SnmpTrap.h"
/*
* Message ::= SEQUENCE {
  msgVersion         INTEGER (3),                    -- SNMPv3
  msgGlobalData      HeaderData,                    -- Global header
  msgSecurityParams  OCTET STRING,                  -- USM security parameters
  msgData            ScopedPduData                  -- Encrypted or plaintext PDU
}

HeaderData ::= SEQUENCE {
  msgID             INTEGER (0..2147483647),        -- Unique message ID
  msgMaxSize        INTEGER (484..2147483647),      -- Max size sender can handle
  msgFlags          OCTET STRING (SIZE(1)),         -- Security flags
  msgSecurityModel  INTEGER                         -- Typically 3 (USM)
}

ScopedPduData ::= CHOICE {
  plaintext         ScopedPDU,                      -- If no privacy
  encryptedPDU      OCTET STRING                    -- If privacy enabled
}

ScopedPDU ::= SEQUENCE {
  contextEngineID   OCTET STRING,                   -- Sender's engine ID
  contextName       OCTET STRING,                   -- Context name
  data              PDU                             -- Actual trap content
}

PDU ::= SEQUENCE {
  pduType           INTEGER,                        -- e.g., SNMPv2-Trap
  requestID         INTEGER,
  errorStatus       INTEGER,
  errorIndex        INTEGER,
  variableBindings  SEQUENCE OF VarBind             -- Trap OIDs and values
}

VarBind ::= SEQUENCE {
  name              OBJECT IDENTIFIER,              -- e.g., snmpTrapOID.0
  value             ANY                             -- e.g., coldStart
}
*/

#define MAGIC_SZ    1024
#define MAGIC_SZ_2  2048

using namespace ReiazDean;
const uint8_t Version[3] = { 0x02, 0x01, 0x03 };
const uint8_t MaxSz[5] = { 0x02, 0x03, 0x00, 0xFF, 0xE3 };
const uint8_t MsgFlags[3] = { 0x04, 0x01, 0x03 };
const uint8_t MsgSecurityModel[3] = { 0x02, 0x01, 0x03 };

//const uint64_t EngineID = 0xAABBCCDDEEFFAABB;
const uint8_t EngineID[8] = { 0xB7, 0x81, 0xFC, 0xC9, 0x5D, 0xB5, 0xB2, 0x2E };//0xB781FCC95DB5B22E
std::atomic<uint32_t> SnmpTrap::s_MsgID = 1001;
std::mutex SnmpTrap::s_Mutex;

void SnmpTrap::SetPwds(Buffer& privPwd, Buffer& authPwd)
{
    std::unique_lock<std::mutex> mlock(s_Mutex);
    s_PrivPwd = privPwd;
    s_PrivPwd.NullTerminate();
    s_AuthPwd = authPwd;
    s_AuthPwd.NullTerminate();
}

Buffer SnmpTrap::GetPrivPwd()
{
    std::unique_lock<std::mutex> mlock(s_Mutex);
    return s_PrivPwd;
}

Buffer SnmpTrap::GetAuthPwd()
{
    std::unique_lock<std::mutex> mlock(s_Mutex);
    return s_AuthPwd;
}

bool
CreateHash(
    WCHAR* pwcALG,
    BCRYPT_ALG_HANDLE& hAlg,
    PBYTE& pbHashObject,
    DWORD& cbHashObject,
    BCRYPT_HASH_HANDLE& hHash)
{
    DWORD cbData = 0;
    DWORD cbHash = 0;
    DWORD status = NTE_FAIL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (status == ERROR_SUCCESS) {
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    }

    if (status == ERROR_SUCCESS) {
        pbHashObject = (PBYTE)calloc(cbHashObject, 1);
    }

    if (pbHashObject) {
        if (ERROR_SUCCESS == BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)) {
            return true;
        }
    }

    return false;
}

void
DestroyHash(
    BCRYPT_HASH_HANDLE& hHash,
    BCRYPT_ALG_HANDLE& hAlg,
    PBYTE& pbHashObject)
{
    if (hHash) {
        BCryptDestroyHash(hHash);
        hHash = NULL;
    }

    if (pbHashObject) {
        free(pbHashObject);
        pbHashObject = NULL;
    }

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
}

bool
password_to_key_sha(
    uint8_t* password,    /* IN */
    uint32_t   passwordlen, /* IN */
    uint8_t* engineID,    /* IN  - pointer to snmpEngineID  */
    uint32_t   engineLength,/* IN  - length of snmpEngineID */
    uint8_t* key)         /* OUT - pointer to caller 20-octet buffer */
{
    uint32_t status = NTE_FAIL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbData = 0;
    DWORD cbHash = 20;
    DWORD cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    BYTE bHash[20];

    uint8_t* cp, password_buf[72];
    uint32_t      password_index = 0;
    uint32_t      count = 0, i;

    if (!CreateHash((WCHAR*)BCRYPT_SHA1_ALGORITHM, hAlg, pbHashObject, cbHashObject, hHash)) {
        return false;
    }

    /**********************************************/
    /* Use while loop until we've done 1 Megabyte */
    /**********************************************/
    while (count < 1048576) {
        cp = password_buf;
        for (i = 0; i < 64; i++) {
            /*************************************************/
            /* Take the next octet of the password, wrapping */
            /* to the beginning of the password as necessary.*/
            /*************************************************/
            *cp++ = password[password_index++ % passwordlen];
        }
        if (BCryptHashData(hHash, password_buf, 64, 0) != ERROR_SUCCESS) {
            DestroyHash(hHash, hAlg, pbHashObject);
            return false;
        }
        count += 64;
    }
    if (BCryptFinishHash(hHash, bHash, cbHash, 0) != ERROR_SUCCESS) {
        DestroyHash(hHash, hAlg, pbHashObject);
        return false;
    }
    //LogBinary(FP, (uint8_t*)"kul:", bHash, cbHash);

    /*****************************************************/
    /* Now localize the key with the engineID and pass   */
    /* through SHA to produce final key                  */
    /* May want to ensure that engineLength <= 32,       */
    /* otherwise need to use a buffer larger than 72     */
    /*****************************************************/
    memcpy(password_buf, bHash, 20);
    memcpy(password_buf + 20, engineID, engineLength);
    memcpy(password_buf + 20 + engineLength, bHash, 20);

    DestroyHash(hHash, hAlg, pbHashObject);

    if (CreateHash((WCHAR*)BCRYPT_SHA1_ALGORITHM, hAlg, pbHashObject, cbHashObject, hHash)) {
        status = BCryptHashData(hHash, password_buf, 40 + engineLength, 0);
        if (status == ERROR_SUCCESS) {
            status = BCryptFinishHash(hHash, key, cbHash, 0);
        }
        DestroyHash(hHash, hAlg, pbHashObject);
        // LogBinary(FP, (uint8_t*)"kul:", key, cbHash);
        return (status == ERROR_SUCCESS);
    }

    return false;
}

SnmpTrap::SnmpTrap()
{
    m_Times = s_MsgID++;
    ReverseMemory((uint8_t*)&m_Times, sizeof(m_Times));
    m_msgAuthoritativeEngineTime.Append((void*)&m_Times, sizeof(m_Times));
    m_msgAuthoritativeEngineTime.ASN1Wrap(UNIVERSAL_TYPE_INT);

    m_Boots = s_MsgID++;
    ReverseMemory((uint8_t*)&m_Boots, sizeof(m_Boots));
    m_msgAuthoritativeEngineBoots.Append((void*)&m_Boots, sizeof(m_Boots));
    m_msgAuthoritativeEngineBoots.ASN1Wrap(UNIVERSAL_TYPE_INT);

    m_msgAuthoritativeEngineID.Append((void*)EngineID, sizeof(EngineID));
    //m_msgAuthoritativeEngineID.Reverse();
    m_msgAuthoritativeEngineID.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);

    {
        Buffer bRand;
        RandomBytes(bRand);
        memset(m_PrivParam, 64, sizeof(m_PrivParam));
        if (bRand.Size() >= sizeof(m_PrivParam)) {
            memcpy(m_PrivParam, (void*)bRand, sizeof(m_PrivParam));
        }
    }
    m_msgPrivacyParameters.Append((void*)m_PrivParam, sizeof(m_PrivParam));
    m_msgPrivacyParameters.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);

    memset(m_AuthParam, 0, sizeof(m_AuthParam));
    m_msgAuthenticationParameters.Append((void*)m_AuthParam, sizeof(m_AuthParam));
    m_msgAuthenticationParameters.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);


    s_MsgID++;
    m_msgUserName.Append((void*)"RDCAuthService", strlen("RDCAuthService"));
    m_msgUserName.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);

    uint32_t tmdID = s_MsgID;
    ReverseMemory((uint8_t*)&tmdID, sizeof(tmdID));
    m_msgGlobalData.Append((void*)&tmdID, sizeof(tmdID));
    m_msgGlobalData.ASN1Wrap(UNIVERSAL_TYPE_INT);
    m_msgGlobalData.Append((void*)MaxSz, sizeof(MaxSz));
    m_msgGlobalData.Append((void*)MsgFlags, sizeof(MsgFlags));
    m_msgGlobalData.Append((void*)MsgSecurityModel, sizeof(MsgSecurityModel));
    m_msgGlobalData.ASN1Wrap(CONSTRUCTED_SEQUENCE);

    memset(m_AESkey, 0, sizeof(m_AESkey));
    memset(m_IV, 0, sizeof(m_IV));
    memset(m_HMACkey, 0, sizeof(m_HMACkey));
    
    //move this
    m_msgSecurityParameters.Append((void*)m_msgAuthoritativeEngineID, m_msgAuthoritativeEngineID.Size());
    m_msgSecurityParameters.Append((void*)m_msgAuthoritativeEngineBoots, m_msgAuthoritativeEngineBoots.Size());
    m_msgSecurityParameters.Append((void*)m_msgAuthoritativeEngineTime, m_msgAuthoritativeEngineTime.Size());
    m_msgSecurityParameters.Append((void*)m_msgUserName, m_msgUserName.Size());
    m_msgSecurityParameters.Append((void*)m_msgAuthenticationParameters, m_msgAuthenticationParameters.Size());
    m_msgSecurityParameters.Append((void*)m_msgPrivacyParameters, m_msgPrivacyParameters.Size());
    m_msgSecurityParameters.ASN1Wrap(CONSTRUCTED_SEQUENCE);
    m_msgSecurityParameters.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
}

SnmpTrap::SnmpTrap(char* pcTrap, uint32_t szTrap) : SnmpTrap()
{
    m_PreDigestedTrap.Clear();
    if (pcTrap) {
        try {
            Buffer bScopedPDU;
            CalculateAESKey((char*)GetPrivPwd());
            CalculateHMACKey((char*)GetAuthPwd());
            CalculateIV();
            ProcessPDU(pcTrap, bScopedPDU);

            m_PreDigestedTrap.Append((void*)Version, sizeof(Version));
            m_PreDigestedTrap.Append(m_msgGlobalData);
            m_PreDigestedTrap.Append(m_msgSecurityParameters);
            m_PreDigestedTrap.Append(m_EncryptedPDU);
            m_PreDigestedTrap.ASN1Wrap(CONSTRUCTED_SEQUENCE);

            DigestMessage();
            ReassembleTrap();
            Send();
        }
        catch (...) {
            m_PreDigestedTrap.Clear();
            m_DigestedTrap.Clear();
        }
    }
}

SnmpTrap::~SnmpTrap() {
    memset(m_AESkey, 0, sizeof(m_AESkey));
    memset(m_IV, 0, sizeof(m_IV));
    memset(m_HMACkey, 0, sizeof(m_HMACkey));
}

int8_t SnmpTrap::DigestMessage()
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int len = SHA_DIGEST_LENGTH;

    memset(digest, 0, sizeof(digest));
    if (HMAC(EVP_sha1(), m_HMACkey, sizeof(m_HMACkey), (uint8_t*)m_PreDigestedTrap, m_PreDigestedTrap.Size(), digest, &len)) {
        memcpy(m_AuthParam, digest, 12);
    }
    return 0;
}

bool SnmpTrap::ReassembleTrap()
{
    m_msgSecurityParameters.Clear();
    m_msgSecurityParameters.Append((void*)m_msgAuthoritativeEngineID, m_msgAuthoritativeEngineID.Size());
    m_msgSecurityParameters.Append((void*)m_msgAuthoritativeEngineBoots, m_msgAuthoritativeEngineBoots.Size());
    m_msgSecurityParameters.Append((void*)m_msgAuthoritativeEngineTime, m_msgAuthoritativeEngineTime.Size());
    m_msgSecurityParameters.Append((void*)m_msgUserName, m_msgUserName.Size());

    m_msgAuthenticationParameters.Clear();
    m_msgAuthenticationParameters.Append((void*)m_AuthParam, sizeof(m_AuthParam));
    m_msgAuthenticationParameters.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
    m_msgSecurityParameters.Append((void*)m_msgAuthenticationParameters, m_msgAuthenticationParameters.Size());

    m_msgSecurityParameters.Append((void*)m_msgPrivacyParameters, m_msgPrivacyParameters.Size());
    m_msgSecurityParameters.ASN1Wrap(CONSTRUCTED_SEQUENCE);
    m_msgSecurityParameters.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);

    m_DigestedTrap.Append((void*)Version, sizeof(Version));
    m_DigestedTrap.Append(m_msgGlobalData);
    m_DigestedTrap.Append(m_msgSecurityParameters);
    m_DigestedTrap.Append(m_EncryptedPDU);
    m_DigestedTrap.ASN1Wrap(CONSTRUCTED_SEQUENCE);

    return true;
}

int SnmpTrap::Send()
{
    try {
        size_t sentLen = 0;
        SOCKET sockfd = 0;
        struct sockaddr_in serverAddr;
        NdacServerConfig& scfg = NdacServerConfig::GetInstance();
        Buffer bIP = scfg.GetValue(SNMP_HOST_STRING);
        Buffer bPort = scfg.GetValue(SNMP_PORT_STRING);
        int port = atoi((char*)bPort);
        // Create UDP socket
        if ((char*)bIP && (m_DigestedTrap.Size() > 0) && (port > 0)) {
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd) {
                // Enable broadcast
                int broadcastEnable = 1;
                if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (char*)&broadcastEnable, sizeof(broadcastEnable)) < 0) {
                    closesocket(sockfd);
                    return 0;
                }

                // Set server address structure
                serverAddr.sin_family = AF_INET;
                serverAddr.sin_port = htons(port);
                InetPtonA(AF_INET, (char*)bIP, &(serverAddr.sin_addr.s_addr));

                // Send data to server
                sentLen = sendto(sockfd, (char*)m_DigestedTrap, m_DigestedTrap.Size(), 0,
                    (struct sockaddr*)&serverAddr, sizeof(serverAddr));

                closesocket(sockfd);
            }
        }

        return (int)sentLen;
    }
    catch (...) {
        return 0;
    }
}

int8_t SnmpTrap::AES_CFB_Encrypt(const uint8_t* plaintext, uint32_t len, Buffer& bOut)
{
    int32_t      p_len = len;
    int32_t      f_len = 0;
    EVP_CIPHER_CTX* ctx = 0;
    uint8_t* pCipher = nullptr;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    bOut.Clear();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), 0, m_AESkey, m_IV)) {
        pCipher = (uint8_t*)calloc(p_len, 1);
        if (pCipher) {
            if (EVP_EncryptUpdate(ctx, pCipher, &p_len, plaintext, len)) {
                bOut.Append(pCipher, len);
            }
            else {
                free(pCipher);
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return bOut.Size();
}

int8_t SnmpTrap::AES_CFB_Decrypt(const uint8_t* ciphertext, uint32_t len, Buffer& bOut)
{
    int32_t      p_len = len;
    int32_t      f_len = 0;
    EVP_CIPHER_CTX* ctx = 0;
    uint8_t* pPlain = nullptr;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    bOut.Clear();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), 0, m_AESkey, m_IV)) {
        pPlain = (uint8_t*)calloc(p_len, 1);
        if (pPlain) {
            if (EVP_DecryptUpdate(ctx, pPlain, &p_len, ciphertext, len)) {
                bOut.Append(pPlain, len);
            }
            else {
                free(pPlain);
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return bOut.Size();
}

void SnmpTrap::CalculateAESKey(char* pcPassword)
{
    uint8_t hash[20];
    if (password_to_key_sha((uint8_t*)pcPassword, (uint32_t)strlen(pcPassword), (uint8_t*)EngineID, sizeof(EngineID), hash)) {
        memcpy(m_AESkey, hash, 16);
    }
}

void SnmpTrap::CalculateHMACKey(char* pcPassword)
{
    uint8_t hash[20];
    if (password_to_key_sha((uint8_t*)pcPassword, (uint32_t)strlen(pcPassword), (uint8_t*)EngineID, sizeof(EngineID), hash)) {
        memcpy(m_HMACkey, hash, 20);
    }
}

void SnmpTrap::CalculateIV()
{
    if (sizeof(m_IV) == (sizeof(m_Boots) + sizeof(m_Times) + sizeof(m_PrivParam))) {
        memcpy(m_IV, &m_Boots, sizeof(m_Boots));
        memcpy(m_IV + sizeof(m_Boots), &m_Times, sizeof(m_Times));
        memcpy(m_IV + sizeof(m_Boots) + sizeof(m_Times), m_PrivParam, sizeof(m_PrivParam));
    }
}

void SnmpTrap::BuildVarBinds(char* pcMessage, Buffer& bVBs)
{
    {
        uint8_t oidTrap[25] = { 0x30 ,0x17, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01,
                                0x00, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x01 };
        bVBs.Append((void*)oidTrap, sizeof(oidTrap));
    }

    {
        uint8_t oidEnt[9] = { 0x06, 0x07, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x3F };//1.3.6.1.4.1.9999
        char cEnt[] = "RDC Inc. AuthService";
        Buffer bVB;

        bVB.Append((void*)cEnt, strlen(cEnt));
        bVB.NullTerminate();
        bVB.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
        bVB.Prepend(oidEnt, sizeof(oidEnt));
        bVB.ASN1Wrap(CONSTRUCTED_SEQUENCE);
        bVBs.Append(bVB);
    }

    {
        uint8_t oidMsg[11] = { 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x3F, 0x01, 0x01 };
        Buffer bVB;

        bVB.Append((void*)pcMessage, strlen(pcMessage));
        bVB.NullTerminate();
        bVB.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
        bVB.Prepend(oidMsg, sizeof(oidMsg));
        bVB.ASN1Wrap(CONSTRUCTED_SEQUENCE);
        bVBs.Append(bVB);
    }

    bVBs.ASN1Wrap(CONSTRUCTED_SEQUENCE);
}

void SnmpTrap::ProcessPDU(char* pcMessage, Buffer& bScopedPDU)
{
    uint8_t trapType[3] = { 0x02, 0x01, 0x07 };
    uint8_t requestId[3] = { 0x02, 0x01, 0x00 };
    uint8_t errorStatus[3] = { 0x02, 0x01, 0x00 };
    uint8_t errorIndex[3] = { 0x02, 0x01, 0x00 };
    Buffer bPDU;
    Buffer bVBs;
    BuildVarBinds(pcMessage, bVBs);

   // bPDU.Append((void*)trapType, 3);
    bPDU.Append((void*)requestId, 3);
    bPDU.Append((void*)errorStatus, 3);
    bPDU.Append((void*)errorIndex, 3);
    bPDU.Append(bVBs);
   // bPDU.ASN1Wrap(CONSTRUCTED_SEQUENCE);
   bPDU.ASN1Wrap(0xA7);//snmpV2-trap         [4] IMPLICIT PDU, choice 4

    {
        Buffer bCID, bCName;
        bCID.Append((void*)"RDCInc", strlen("RDCInc"));
        bCID.NullTerminate();
        bCID.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);

        bCName.Append((void*)"Authorization Service", strlen("Authorization Service"));
        bCName.NullTerminate();
        bCName.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);

        bScopedPDU.Append(bCID);
        bScopedPDU.Append(bCName);
        bScopedPDU.Append(bPDU);
        bScopedPDU.ASN1Wrap(CONSTRUCTED_SEQUENCE);

        AES_CFB_Encrypt((uint8_t*)bScopedPDU, bScopedPDU.Size(), m_EncryptedPDU);
        m_EncryptedPDU.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
    }

    return;
}
/*
SNMPv2-Trap-PDU ::= SEQUENCE {
    request-id         INTEGER,
    error-status       INTEGER,
    error-index        INTEGER,
    variable-bindings  SEQUENCE OF VarBind
}

ScopedPDU ::= SEQUENCE {
    contextEngineID  OCTET STRING,
    contextName      OCTET STRING,
    data             PDUs
}

PDUs ::= CHOICE {
    get-request         [0] IMPLICIT PDU,
    get-next-request    [1] IMPLICIT PDU,
    get-response        [2] IMPLICIT PDU,
    set-request         [3] IMPLICIT PDU,
    snmpV2-trap         [4] IMPLICIT PDU,
    inform-request      [6] IMPLICIT PDU,
    report              [8] IMPLICIT PDU
}
*/

#ifdef _DEBUG
void SnmpTrap::KnownKeyTests()
{
    uint8_t engn[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
    char password[] = "maplesyrup";
    uint8_t hash[20];

    if (password_to_key_sha((uint8_t*)password, (uint32_t)strlen(password), (uint8_t*)engn, sizeof(engn), hash)) {
        LogBinary(stdout, (uint8_t*)"key = \n", (uint8_t*)hash, 20);
        printf("expected = %s\n", "66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f");
    }

}

void SnmpTrap::DecryptionTest()
{
    /*
    * Output taken from CentOS after running:
    * snmptrap -v 3 -l authPriv -u username -a SHA -A auth_password -x AES -X priv_password -e 0x8000000001020304 192.168.0.103 '' SNMPv2-MIB::coldStart SNMPv2-MIB::sysName.0 s "MyDevice"
    */
    Buffer bPlain;
    char user[] = "username";
    char authP[] = "auth_password";
    char privP[] = "priv_password";
    uint8_t engine[8] = { 0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
    uint8_t privParm[8] = { 0x20, 0x60, 0x6C, 0x52, 0x63, 0xBE, 0xF0, 0xFC };
    uint8_t boots[4] = { 0x00, 0x00, 0x00, 0x01 };
    uint8_t times[4] = { 0x00, 0x88, 0xC6, 0xE2 };
    uint8_t encrypted[] = {
0x36, 0x1A, 0x80, 0xBE, 0x30, 0x79, 0xBC, 0x1F,
0xEB, 0x7D, 0xE6, 0x7D, 0xAD, 0x98, 0x26, 0xBD,
0xA6, 0x56, 0xDC, 0x2A, 0x45, 0x22, 0x69, 0xD1,
0xF7, 0xFB, 0x69, 0x79, 0xCC, 0x9A, 0xE5, 0xD9,
0x7F, 0xA8, 0x03, 0xBA, 0x19, 0x94, 0xFF, 0xAB,
0x9F, 0xA8, 0x0A, 0x92, 0x76, 0xB3, 0x25, 0x89,
0x80, 0x03, 0xE0, 0x96, 0x81, 0x73, 0xFF, 0xF5,
0x1F, 0x93, 0x68, 0x24, 0x9C, 0xDB, 0x65, 0x1C,
0x33, 0x67, 0x78, 0x0F, 0x53, 0xE7, 0x5A, 0x74,
0xDD, 0xA1, 0xF0, 0x14, 0x9B, 0x1F, 0x25, 0x74,
0x31, 0xF1, 0xA6, 0x68, 0x85, 0xC4, 0x48, 0x91,
0x08, 0xC7, 0xB2, 0xEC, 0x99, 0xAA, 0x70, 0x07,
0x60, 0xF2, 0xEE, 0x01, 0x9D, 0xA7, 0xF0, 0xD9
    };

    {
        uint8_t hash[20];
        if (password_to_key_sha((uint8_t*)privP, (uint32_t)strlen(privP), (uint8_t*)engine, sizeof(engine), hash)) {
            memcpy(m_AESkey, hash, 16);
        }
    }

    memcpy(m_IV, boots, sizeof(boots));
    memcpy(m_IV + sizeof(boots), times, sizeof(times));
    memcpy(m_IV + sizeof(boots) + sizeof(times), privParm, sizeof(privParm));

    AES_CFB_Decrypt(encrypted, 104, bPlain);
    LogBinary(stdout, (uint8_t*)"aaa", (uint8_t*)bPlain, bPlain.Size());

}
#endif