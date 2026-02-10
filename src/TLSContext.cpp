/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include <sys/types.h>
#include <sys/stat.h>
#include "Utils.h"
#include "TLSContext.h"
#include "SequenceReader.h"
#include "x509class.h"
#ifdef _WIN_UI
//#include <WinSock2.h>
#endif

using namespace ReiazDean;

std::mutex TLSContext::s_MutexVar;
std::condition_variable TLSContext::s_ConditionVar;
std::unique_ptr<RSAPublicKey> TLSContext::s_RSAPublicKeyCA = nullptr;

bool TLSContext::CreateRSAPublicKey(char* caCertBundle)
{
    try {
        Buffer bCAcert;
        uint32_t sz = 0;

        if (readFile(caCertBundle, bCAcert) <= 0) {
            return false;
        }
        if (PEMcert_to_DERcert(bCAcert, sz)) {
            Buffer bPK;
            SequenceReaderX	seq;
            Certificate ca(bCAcert);
            ca.GetPublicKeyInfo(bPK);

            if (seq.Initilaize(bPK)) {
                Buffer bPubKey;
                Buffer bTemp;
                SequenceReaderX s2;
                if (seq.getValueAt(1, bTemp)) {
                    uint8_t* p = (uint8_t*)bTemp;
                    sz = bTemp.Size();
                    if (p[0] == 0) {//ASN BIT STRINGS(0x03) MUST CARRY A UNUSED BITS BYTE. THIS MUST BE ZERO FOR RSA VALUES
                        p++;
                        sz--;
                    }
                    bPubKey.Append(p, sz);
                }
                if (s2.Initilaize(bPubKey)) {
                    BCRYPT_RSAKEY_BLOB pubBlob = { BCRYPT_RSAPUBLIC_MAGIC, 2048, 0, 0, 0, 0 };
                    Buffer bMod, bExp;
                    if (!s2.getValueAt(0, bMod)) {
                        return false;
                    }
                    if (!s2.getValueAt(1, bExp)) {
                        return false;
                    }
                    pubBlob.cbModulus = bMod.Size();
                    pubBlob.cbPublicExp = bExp.Size();
                    bPubKey.Clear();
                    bPubKey.Append((void*)&pubBlob, sizeof(BCRYPT_RSAKEY_BLOB));
                    bPubKey.Append(bExp);
                    bPubKey.Append(bMod);
                    s_RSAPublicKeyCA = std::make_unique<RSAPublicKey>((uint8_t*)bPubKey, bPubKey.Size());
                    return (s_RSAPublicKeyCA != nullptr);
                }
            }
        }
    }
    catch (...) {
        s_RSAPublicKeyCA = nullptr;
        return false;
    }

    return false;
}

bool TLSContext::VerifyCertWithBundle(char* pcBundleFile, const uint8_t* pcCertData, uint32_t szCertData)
{
    try {
        bool bRc = false;
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        if (!s_RSAPublicKeyCA) {
            CreateRSAPublicKey(pcBundleFile);
        }

        if (s_RSAPublicKeyCA && pcCertData) {
            Buffer bCert;
            SequenceReaderX s;
            bCert.Append((void*)pcCertData, szCertData);
            if (s.Initilaize(bCert)) {
                SECURITY_STATUS ss = NTE_FAIL;
                uint8_t* p;
                uint32_t sz;
                BCRYPT_PKCS1_PADDING_INFO pi;
                Buffer tbs, sig, hash;
                s.getElementAt(0, tbs);
                s.getValueAt(2, sig);
                Sha256((uint8_t*)tbs, tbs.Size(), hash);
                pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                p = (uint8_t*)sig;
                sz = sig.Size();
                if (p[0] == 0) {//ASN BIT STRINGS(0x03) MUST CARRY A UNUSED BITS BYTE. THIS MUST BE ZERO FOR RSA VALUES
                    p++;
                    sz--;
                }
                ss = s_RSAPublicKeyCA->VerifySignature(&pi, (uint8_t*)hash, hash.Size(), p, sz, BCRYPT_PAD_PKCS1);
                bRc = (ERROR_SUCCESS == ss);
            }
        }

        return bRc;
    }
    catch (...) {
        return false;
    }
}

bool TLSContext::VerifySignatureWithCA(char* pcBundleFile, uint8_t* hash, uint32_t szHash, uint8_t* signature, uint32_t szSignature)
{
    try {
        bool bRc = false;
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        if (!s_RSAPublicKeyCA) {
            CreateRSAPublicKey(pcBundleFile);
        }

        if (s_RSAPublicKeyCA && hash && signature) {
            SECURITY_STATUS ss = NTE_FAIL;
            BCRYPT_PKCS1_PADDING_INFO pi;
            pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            ss = s_RSAPublicKeyCA->VerifySignature(&pi, (uint8_t*)hash, szHash, signature, szSignature, BCRYPT_PAD_PKCS1);
            bRc = (ERROR_SUCCESS == ss);
        }

        return bRc;
    }
    catch (...) {
        return false;
    }

}

/******************************************************************************************
Constructor			TLSContext(char* hostname, int port)
Parameters:			(char* hostname, int port)

Description:		Construct an instance with specified inputs

*******************************************************************************************/
TLSContext::TLSContext()
{
    m_ssl = nullptr;
    m_sock = 0;
    memset(m_nonce, 0, sizeof(m_nonce));
}

/******************************************************************************************
Destructor			~TLSContext()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
TLSContext::~TLSContext()
{
    Shutdown();
}

void TLSContext::Shutdown()
{
    std::unique_lock<std::mutex> mlock(s_MutexVar);
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
    }
   
    if (m_sock) {
        CloseSocket(m_sock);
    }

    m_ssl = nullptr;
    m_sock = 0;

}

int TLSContext::ReadAppend(Buffer &b)
{
    int       len = 0;
    char      buff[FILE_TRANSFER_CHUNK_SZ] = {};

    len = SSL_read(m_ssl, buff, sizeof(buff));
    if (len > 0) {
        b.Append(buff, len);
    }

    return len;
}

int TLSContext::DoNonBlockingReadEx(Buffer &b, int timeout)
{
    int       len = 0;
    int       err = SSL_ERROR_WANT_READ;
    int       tries = 0;
   
    if (!m_ssl || !m_sock) {
        return -1;
    }

    SetToNotBlock(m_sock);
    if (0 > Select(m_sock, timeout, 0, true)) {
        return -1;
    }

    do {
        len = ReadAppend(b);
        err = SSL_get_error(m_ssl, len);
        switch (err) {
        case SSL_ERROR_NONE:
            return b.Size();
        case SSL_ERROR_WANT_READ:
            if (0 > Select(m_sock, 1, 0, true)) {
                return -1;
            }
            break;
        case SSL_ERROR_WANT_WRITE:
            if (0 > Select(m_sock, 1, 0, false)) {
                return -1;
            }
            break;
        default:
            Shutdown();
            return -1;
        }

        tries++;
    } while (tries < MAX_WANT_TRIES);

    return -1;
}

int TLSContext::DoNonBlockingRead(Buffer& b, int timeout)
{
    int       len = 0;
    
    do {
        Buffer t;
        len = DoNonBlockingReadEx(t, timeout);
        b.Append(t);
    } while (len == FILE_TRANSFER_CHUNK_SZ);

    return b.Size();
}

int TLSContext::DoNonBlockingWriteEx(char* pcData, int szData, int timeout)
{
    int       err = SSL_ERROR_WANT_WRITE;
    int       written = 0;
    int       tries = 0;
    
    if (!m_ssl || !m_sock) {
        return -1;
    }

    SetToNotBlock(m_sock);
    if (0 > Select(m_sock, timeout, 0, false)) {
        return -1;
    }

    do {
        int len = SSL_write(m_ssl, pcData + written, minimum(FILE_TRANSFER_CHUNK_SZ, szData - written));
        err = SSL_get_error(m_ssl, len);
        switch (err) {
        case SSL_ERROR_NONE:
            written += len;
            tries = 0;
            if (written >= szData) {
                return written;
            }
            break;
        case SSL_ERROR_WANT_READ:
            if (0 > Select(m_sock, 1, 0, true)) {
                return -1;
            }
            break;
        case SSL_ERROR_WANT_WRITE:
            if (0 > Select(m_sock, 1, 0, false)) {
                return -1;
            }
            break;
        default:
            Shutdown();
            return -1;
        }

        tries++;
    } while (tries < MAX_WANT_TRIES);

    return written;
}

int TLSContext::DoNonBlockingWrite(Buffer &b, int timeout)
{
    return DoNonBlockingWriteEx((char*)b, b.Size(), timeout);
}

int TLSContext::BlockingRead(Buffer& b, int size)
{
    int r = 0;

    SetToBlock(m_sock);
    r = SSL_read(m_ssl, (void*)b, size);
    SetToNotBlock(m_sock);

    return r;
}

int TLSContext::BlockingWrite(Buffer& b, int size)
{
    int r = 0;

    SetToBlock(m_sock);
    r = SSL_write(m_ssl, (void*)b, size);
    SetToNotBlock(m_sock);

    return r;
}


