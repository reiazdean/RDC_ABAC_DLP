/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "pch.h"
#undef API_H
#undef KEM_H
extern "C" {
#include "../CrystalsKyber/ref/api.h"
#include "../CrystalsKyber/ref/kem.h"
}
#include "Utils.h"
#include "KyberKeyPair.h"

using namespace ReiazDean;

bool KyberKeyPair::Test()
{
    Buffer bWrapped;
    KyberKeyPair alice;
    KyberKeyPair bob;
    uint8_t test[] = "abcdefghijklmonpqrstuvwxyz\n";
    Buffer bEnc, bPlain;

    alice.Create();
    bob.WrapRandomAESkey(alice.GetPublicKey(), alice.GetPublicKeySize(), bWrapped);
    alice.UnwrapAESKey(bWrapped);

    bob.AES_Encrypt(test, (uint32_t)strlen((char*)test), bEnc);
    alice.AES_Decrypt((uint8_t*)bEnc, bEnc.Size(), bPlain);

    return strlen((char*)test) == bPlain.Size();
}

/******************************************************************************************
Constructor			KyberKeyPair
Parameters:

Description:		Construct an instance with specified inputs

*******************************************************************************************/
KyberKeyPair::KyberKeyPair()
{
    m_PrivKey.Clear();
    m_PubKey.Clear();
    m_Alg = ALG_KYBER;
}

/******************************************************************************************
Destructor			~KyberKeyPair()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
KyberKeyPair::~KyberKeyPair()
{
    m_PrivKey.Clear();
    m_PubKey.Clear();
}

KyberKeyPair& KyberKeyPair::operator=(const KyberKeyPair &original) {
    std::unique_lock<std::mutex> mlock(m_Mutex);
    m_PrivKey = original.m_PrivKey;
    m_PubKey = original.m_PubKey;
    return *this;
}

/******************************************************************************************
Function			Create()
Parameters:			
*******************************************************************************************/
int32_t KyberKeyPair::Create()
{
    
    try {
        uint8_t pub[CRYPTO_PUBLICKEYBYTES];
        uint8_t sec[CRYPTO_SECRETKEYBYTES];
        crypto_kem_keypair(pub, sec);
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

void KyberKeyPair::LockPages()
{
    m_Secret.LockPages();
}

/******************************************************************************************
Function			WrapRandomAESkey
Parameters:			uint8_t* pcPubKey, int32_t szPubKey
*******************************************************************************************/
int8_t KyberKeyPair::WrapRandomAESkey(uint8_t* pcPubKey, int32_t szPubKey, Buffer& bWrappedKey)
{
    int       r = -1;

    try {
        uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
        Buffer b;
        RandomBytes(b);
        m_Secret.Clear();
        m_Secret.Append((uint8_t*)b, CRYPTO_BYTES);
        crypto_kem_enc(ct, (uint8_t*)m_Secret, pcPubKey);
        bWrappedKey.Append(ct, CRYPTO_CIPHERTEXTBYTES);
    }
    catch (...) {
        m_Secret.Clear();
        bWrappedKey.Clear();
        return -1;
    }
      
    return bWrappedKey.Size();
}

/******************************************************************************************
Function			UnwrapAESKey
Parameters:			Buffer bWrappedKey
*******************************************************************************************/
int8_t KyberKeyPair::UnwrapAESKey(Buffer bWrappedKey)
{
    uint8_t ss[CRYPTO_BYTES];
    m_Secret.Clear();

    try {
        crypto_kem_dec(ss, (uint8_t*)bWrappedKey, m_PrivKey);
        m_Secret.Append(ss, CRYPTO_BYTES);
    }
    catch (...) {
        m_Secret.Clear();
        return -1;
    }

    return m_Secret.Size();
}

uint32_t KyberKeyPair::AES_Encrypt(uint8_t *plaintext, uint32_t len, Buffer& bEnc)
{
    try {
        Buffer b;
        if (SHA384_DIGEST_LENGTH == Sha384((uint8_t*)m_Secret, m_Secret.Size(), b)) {
            return AES_CBC_Encrypt((uint8_t*)b, (uint8_t*)b + 32, plaintext, len, bEnc);
        }
        return 0;
    }
    catch (...) {
        bEnc.Clear();
        return 0;
    }
}

uint32_t  KyberKeyPair::AES_Decrypt(uint8_t *ciphertext, uint32_t len, Buffer& bPlain)
{
    try {
        Buffer b;
        if (SHA384_DIGEST_LENGTH == Sha384((uint8_t*)m_Secret, m_Secret.Size(), b)) {
            return AES_CBC_Decrypt((uint8_t*)b, (uint8_t*)b + 32, ciphertext, len, bPlain);
        }
        return 0;
    }
    catch (...) {
        bPlain.Clear();
        return 0;
    }
}



