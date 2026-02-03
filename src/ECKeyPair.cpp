/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "ECKeyPair.h"

using namespace ReiazDean;

/*
IMPORTANT READING
https://tools.ietf.org/html/rfc7696
https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
*/

/******************************************************************************************
Constructor			ECKeyPair
Parameters:

Description:		Construct an instance with specified inputs

*******************************************************************************************/
ECKeyPair::ECKeyPair()
{
    m_alg = NID_secp384r1;
    m_eckey = nullptr;
    if (Create() == 1)
    {
        GetCoordinates();
    }
}

ECKeyPair::ECKeyPair(int alg)
{
    m_alg = alg;
    m_eckey = nullptr;
    if (Create() == 1)
    {
        GetCoordinates();
    }
}

/******************************************************************************************
Destructor			~ECKeyPair()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
ECKeyPair::~ECKeyPair()
{
    m_Secret.Clear();
    m_PubKeyBytes.Clear();

    if (m_eckey)
        EVP_PKEY_free(m_eckey);
}

/******************************************************************************************
Function			Create()
Parameters:			NID_X9_62_prime256v1,  NID_secp384r1,  NID_secp521r1
*******************************************************************************************/
int32_t ECKeyPair::Create()
{
    switch (m_alg) {
    case NID_X9_62_prime256v1:
        m_eckey = EVP_EC_gen("prime256v1");
        break;
    case NID_secp384r1:
        m_eckey = EVP_EC_gen("secp384r1");
        break;
    case NID_secp521r1:
        m_eckey = EVP_EC_gen("secp521r1");
        break;
    default:
        return -1;
    }

    if (m_eckey) {
        return 1;
    }
    
    return -1;
}

/******************************************************************************************
Function			GetCoordinates()
Parameters:
*******************************************************************************************/
void ECKeyPair::GetCoordinates()
{
    size_t pubKeyBytesSz = 0;

    try {
        m_PubKeyBytes.Clear();
        if (EVP_PKEY_get_octet_string_param(m_eckey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubKeyBytesSz))
        {
            Buffer b(pubKeyBytesSz);
            if (EVP_PKEY_get_octet_string_param(m_eckey, OSSL_PKEY_PARAM_PUB_KEY, (uint8_t*)b, pubKeyBytesSz, &pubKeyBytesSz))
            {
                m_PubKeyBytes.Append((uint8_t*)b, pubKeyBytesSz);
            }
        }
    }
    catch (...) {
        return;
    }

    return;
}

/******************************************************************************************
Function			SignHash
Parameters:			uint8_t* pcHash, int32_t szHash, uint8_t* pbOutput, int32_t cbOutput, int32_t *pcbResult
*******************************************************************************************/
int8_t ECKeyPair::SignHash(uint8_t* pcHash, int32_t szHash, uint8_t* pbOutput, int32_t cbOutput, int32_t *pcbResult)
{
    return -1;
}

/******************************************************************************************
Function			VerifySignature
Parameters:			uint8_t* pcHash, int32_t szHash, uint8_t* pbSig, int32_t cbSig
*******************************************************************************************/
int8_t ECKeyPair::VerifySignature(uint8_t* pcHash, int32_t szHash, uint8_t* pbSig, int32_t cbSig)
{
    return -1;
}

/******************************************************************************************
Function			CalculateSecret
Parameters:			EVP_PKEY* publicECkey
*******************************************************************************************/
size_t ECKeyPair::CalculateSecret(EVP_PKEY* publicECkey)
{
    size_t secret_size = -1;
    int r = -1;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_eckey, 0);
    if (ctx) {
        try {
            if (EVP_PKEY_derive_init(ctx) == 1) {
                if (EVP_PKEY_derive_set_peer(ctx, publicECkey) == 1) {
                    if (EVP_PKEY_derive(ctx, 0, &secret_size) == 1) {
                        Buffer secret(secret_size);
                        if ((EVP_PKEY_derive(ctx, (uint8_t*)secret, &secret_size)) == 1) {
                            m_Secret.Clear();
                            m_Secret.Append((uint8_t*)secret, secret_size);
                        }
                    }
                }
            }
            EVP_PKEY_CTX_free(ctx);
        }
        catch (...) {
            EVP_PKEY_CTX_free(ctx);
            m_Secret.Clear();
            return -1;
        }
    }

    return secret_size;
}

void ECKeyPair::LockPages()
{
    m_Secret.LockPages();
}

EVP_PKEY* ECKeyPair::ImportPubKey(uint8_t* pcPubKey, int32_t szPubKey, const char* alg)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = nullptr;
    OSSL_PARAM_BLD *param_bld = nullptr;
    OSSL_PARAM *params = nullptr;
    int exitcode = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx) {
        param_bld = OSSL_PARAM_BLD_new();
    }

    if (param_bld) {
        OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", alg, 0);
        OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pcPubKey, szPubKey);
        params = OSSL_PARAM_BLD_to_param(param_bld);
        OSSL_PARAM_BLD_free(param_bld);
    }

    if (params) {
        if (EVP_PKEY_fromdata_init(ctx) > 0) {
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        }
        OSSL_PARAM_free(params);
    }
    
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return pkey;
}

/******************************************************************************************
Function			DeriveAESkey
Parameters:			uint8_t* pcPubKey, int32_t szPubKey
*******************************************************************************************/
int8_t ECKeyPair::DeriveAESkey(uint8_t* pcPubKey, int32_t szPubKey)
{
    int       r = -1;
    EVP_PKEY* eckey = nullptr;

    if (pcPubKey == nullptr)
    {
        return -1;
    }

    if (szPubKey != m_PubKeyBytes.Size())
    {
        return -2;
    }

    switch (m_alg) {
    case NID_X9_62_prime256v1:
        eckey = ImportPubKey(pcPubKey, szPubKey, "prime256v1");
        break;
    case NID_secp384r1:
        eckey = ImportPubKey(pcPubKey, szPubKey, "secp384r1");
        break;
    case NID_secp521r1:
        eckey = ImportPubKey(pcPubKey, szPubKey, "secp521r1");
        break;
    default:
        return -3;
    }

    if (!eckey) {
        return -4;
    }

    CalculateSecret(eckey);
    EVP_PKEY_free(eckey);
    
    return 0;
}

uint32_t ECKeyPair::AES_Encrypt(uint8_t *plaintext, uint32_t len, Buffer& bEnc)
{
    try {
        Buffer b;
        Sha384((uint8_t*)m_Secret, m_Secret.Size(), b);
        return AES_CBC_Encrypt((uint8_t*)b, (uint8_t*)b + 32, plaintext, len, bEnc);
    }
    catch (...) {
        bEnc.Clear();
        return 0;
    }
}

uint32_t  ECKeyPair::AES_Decrypt(uint8_t *ciphertext, uint32_t len, Buffer& bPlain)
{
    try {
        Buffer b;
        Sha384((uint8_t*)m_Secret, m_Secret.Size(), b);
        return AES_CBC_Decrypt((uint8_t*)b, (uint8_t*)b + 32, ciphertext, len, bPlain);
    }
    catch (...) {
        bPlain.Clear();
        return 0;
    }
}



