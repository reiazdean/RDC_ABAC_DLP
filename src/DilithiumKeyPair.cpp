/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "pch.h"
#include "DilithiumKeyPair.h"
#undef API_H
#undef PARAMS_H
extern "C" {
#include "Dilithium/api.h"
#include "Dilithium/params.h"
#include "Dilithium/sign.h"
#include "Dilithium/randombytes.h"   // Random generator
}

using namespace ReiazDean;

#define CTXLEN 14

bool DilithiumKeyPair::Test()
{
    DilithiumKeyPair alice;
    DilithiumKeyPair bob;
    char test[4096];
    Buffer bData, bSig;
    size_t sz = 0;

    if (!alice.Open((char*)"C:\\Users\\Public\\aliceSecret.dat", (char*)"C:\\Users\\Public\\alicePublic.dat", (char*)"abc123")) {
        alice.Create();
        alice.Persist((char*)"C:\\Users\\Public\\aliceSecret.dat", (char*)"C:\\Users\\Public\\alicePublic.dat", (char*)"abc123");
    }

    memset(test, 'a', sizeof(test));
    bData.Append((void*)test, sizeof(test));
    sz = alice.Sign(bData, bSig);

    if (bob.ReadPublic((char*)"C:\\Users\\Public\\alicePublic.dat")) {
        return bob.Verify(bData, bSig);
    }
    return false;
}

/******************************************************************************************
Constructor			DilithiumKeyPair
Parameters:

Description:		Construct an instance with specified inputs

*******************************************************************************************/
DilithiumKeyPair::DilithiumKeyPair()
{
    m_PrivKey.Clear();
    m_PubKey.Clear();
    m_Alg = ALG_DILITHIUM;
}

/******************************************************************************************
Destructor			~DilithiumKeyPair()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
DilithiumKeyPair::~DilithiumKeyPair()
{
    m_PrivKey.Clear();
    m_PubKey.Clear();
}

DilithiumKeyPair& DilithiumKeyPair::operator=(const DilithiumKeyPair &original) {
    std::unique_lock<std::mutex> mlock(m_Mutex);
    m_PrivKey = original.m_PrivKey;
    m_PubKey = original.m_PubKey;
    return *this;
}

/******************************************************************************************
Function			Create()
Parameters:			
*******************************************************************************************/
int32_t DilithiumKeyPair::Create()
{
    
    try {
        uint8_t pub[CRYPTO_PUBLICKEYBYTES];
        uint8_t sec[CRYPTO_SECRETKEYBYTES];
        crypto_sign_keypair(pub, sec);
        m_PrivKey.Append((void*)sec, CRYPTO_SECRETKEYBYTES);
        m_PubKey.Append((void*)pub, CRYPTO_PUBLICKEYBYTES);
        memset(sec, 0, CRYPTO_SECRETKEYBYTES);
        return 0;
    }
    catch (...) {
        m_PrivKey.Clear();
        m_PubKey.Clear();
        return -1;
    }
    
    return -1;
}

/******************************************************************************************
Function			Sign
Parameters:			Buffer bData, Buffer& bSignature
*******************************************************************************************/
uint32_t DilithiumKeyPair::Sign(const Buffer& bData, Buffer& bSignature)
{
    size_t sigSz = 0;

    bSignature.Clear();
    try {
        uint8_t ctx[CTXLEN] = { 0 };
        uint8_t sig[CRYPTO_BYTES + SHA512_DIGEST_LENGTH];
        Buffer bHash;
        Buffer bTmp = bData;
        Sha512((uint8_t*)bTmp, bTmp.Size(), bHash);
        snprintf((char*)ctx, CTXLEN, "ReiazDeanInc");
        crypto_sign(sig, &sigSz, (uint8_t*)bHash, bHash.Size(), ctx, CTXLEN, (uint8_t*)m_PrivKey);
        bSignature.Append(sig, sigSz);
    }
    catch (...) {
        bSignature.Clear();
        return 0;
    }
      
    return (uint32_t)sigSz;
}

/******************************************************************************************
Function			Verify
Parameters:			Buffer bData, Buffer bSignature
*******************************************************************************************/
bool DilithiumKeyPair::Verify(const Buffer& bData, const Buffer bSignature)
{
    uint8_t ctx[CTXLEN] = { 0 };
    uint8_t m_out[SHA512_DIGEST_LENGTH];
    size_t m_out_len = SHA512_DIGEST_LENGTH;
    snprintf((char*)ctx, CTXLEN, "ReiazDeanInc");
    Buffer bTmpSig = bSignature;

    try {
        if (0 == crypto_sign_open(m_out, &m_out_len, (uint8_t*)bTmpSig, bTmpSig.Size(), ctx, CTXLEN, (uint8_t*)m_PubKey)) {
            Buffer bHash;
            Buffer bTmp = bData;
            Sha512((uint8_t*)bTmp, bTmp.Size(), bHash);
            if (memcmp(m_out, (uint8_t*)bHash, m_out_len) == 0) {
                return true;
            }
        }

    }
    catch (...) {
        return false;
    }

    return false;
}

/******************************************************************************************
Function			PersistSecret
Parameters:			char* pcSecretFile
*******************************************************************************************/
bool DilithiumKeyPair::PersistSecret(char* pcFile, char* pcPassword)
{
    Buffer bHash;
    Buffer bEnc;
    Sha384((uint8_t*)pcPassword, (uint32_t)strlen(pcPassword), bHash);
    try {
        AES_CBC_Encrypt((uint8_t*)bHash, (uint8_t*)bHash + 32, (uint8_t*)m_PrivKey, m_PrivKey.Size(), bEnc);
    }
    catch (...) {
        return false;
    }
    return (1 == saveToFile((int8_t*)pcFile, (int8_t*)bEnc, bEnc.Size()));
}
/******************************************************************************************
Function			PersistPublic
Parameters:			char* pcPublicFile
*******************************************************************************************/
bool DilithiumKeyPair::PersistPublic(char* pcFile)
{
    return (1 == saveToFile((int8_t*)pcFile, (int8_t*)m_PubKey, m_PubKey.Size()));
}

/******************************************************************************************
Function			OpenSecret
Parameters:			char* pcSecretFile
*******************************************************************************************/
bool DilithiumKeyPair::OpenSecret(char* pcFile, char* pcPassword)
{
    Buffer bHash;
    Buffer bEnc;
    Sha384((uint8_t*)pcPassword, (uint32_t)strlen(pcPassword), bHash);
    if (readFile(pcFile, bEnc) > 0) {
        try {
            AES_CBC_Decrypt((uint8_t*)bHash, (uint8_t*)bHash + 32, (uint8_t*)bEnc, bEnc.Size(), m_PrivKey);
        }
        catch (...) {
            return false;
        }
        return (m_PrivKey.Size() > 0);
    }
    return false;
}

/******************************************************************************************
Function			OpenPublic
Parameters:			char* pcPublicFile
*******************************************************************************************/
bool DilithiumKeyPair::OpenPublic(char* pcFile)
{
    return (readFile(pcFile, m_PubKey) > 0);
}

/******************************************************************************************
Function			Persist
Parameters:			char* pcSecretFile, char* pcPublicFile
*******************************************************************************************/
bool DilithiumKeyPair::Persist(char* pcSecretFile, char* pcPublicFile, char* pcPassword)
{
    return PersistSecret(pcSecretFile, pcPassword) && PersistPublic(pcPublicFile);
}

/******************************************************************************************
Function			Open
Parameters:			char* pcSecretFile, char* pcPublicFile
*******************************************************************************************/
bool DilithiumKeyPair::Open(char* pcSecretFile, char* pcPublicFile, char* pcPassword)
{
    if (pcSecretFile && pcPublicFile && pcPassword) {
        return OpenSecret(pcSecretFile, pcPassword) && OpenPublic(pcPublicFile);
    }
    return false;
}
