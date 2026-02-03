/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "RSAPublicKey.h"

using namespace ReiazDean;

/******************************************************************************************
Constructor			RSAPublicKey
Parameters:			char* pcPubCookie, int pubLen, char* pcPrivCookie, int privLen

Description:		Construct an instance with specified inputs

*******************************************************************************************/
RSAPublicKey::RSAPublicKey(uint8_t* pbData, size_t cbData)
{
    m_bPublicKey.Append(pbData, cbData);
}

/******************************************************************************************
Destructor			~RSAPublicKey()
Parameters:			none

Description:		Destroys an instance

*******************************************************************************************/
RSAPublicKey::~RSAPublicKey()
{
}

/******************************************************************************************
Function			VerifySignature
Parameters:			( LPCWSTR pwcName, PBYTE pbValue )
*******************************************************************************************/
SECURITY_STATUS RSAPublicKey::VerifySignature( VOID *pPaddingInfo,
	                                          PBYTE pbHashValue,
											  DWORD cbHashValue,
											  PBYTE pbSignature,
											  DWORD cbSignature,
											  DWORD dwFlags )
{
    NCRYPT_PROV_HANDLE			hProviderMS = 0;
    NCRYPT_PROV_HANDLE			hKeyMS = 0;
    SECURITY_STATUS				ss = NTE_FAIL;

  
    try {
        ss = NCryptOpenStorageProvider(&hProviderMS, MS_KEY_STORAGE_PROVIDER, 0);
        if (ss == ERROR_SUCCESS) {
            ss = NCryptImportKey(hProviderMS, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, &hKeyMS, (uint8_t*)m_bPublicKey, m_bPublicKey.Size(), 0);
        }

        if (ss == ERROR_SUCCESS) {
            ss = NCryptVerifySignature(hKeyMS, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags);
        }
    }
    catch (...) {
        ss = NTE_FAIL;
    }

    if (hKeyMS)
    {
        NCryptFreeObject(hKeyMS);
    }

    if (hProviderMS)
    {
        NCryptFreeObject(hProviderMS);
    }

    return ss;
}

/******************************************************************************************
Function			Encrypt
Parameters:			( LPCWSTR pwcName, PBYTE pbValue )
*******************************************************************************************/
SECURITY_STATUS RSAPublicKey::Encrypt(PBYTE pbInput, DWORD cbInput, Buffer& bEnc)
{
    NCRYPT_PROV_HANDLE hProviderMS = 0;
    NCRYPT_PROV_HANDLE hKeyMS = 0;
    //BCRYPT_PKCS1_PADDING_INFO pi;
    DWORD dwSize = 0;
    SECURITY_STATUS ss = NTE_FAIL;

    bEnc.Clear();
    try {
        ss = NCryptOpenStorageProvider(&hProviderMS, MS_KEY_STORAGE_PROVIDER, 0);
        if (ss == ERROR_SUCCESS) {
            ss = NCryptImportKey(hProviderMS, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, &hKeyMS, (uint8_t*)m_bPublicKey, m_bPublicKey.Size(), 0);
        }

        if (ss == ERROR_SUCCESS) {
            ss = NCryptEncrypt(hKeyMS, pbInput, cbInput, NULL, NULL, 0, &dwSize, BCRYPT_PAD_PKCS1);
        }

        if (ss == ERROR_SUCCESS) {
            Buffer b(dwSize);
            ss = NCryptEncrypt(hKeyMS, pbInput, cbInput, NULL, (uint8_t*)b, dwSize, &dwSize, BCRYPT_PAD_PKCS1);
            if (ss == ERROR_SUCCESS) {
                bEnc.Append((void*)b, dwSize);
            }
        }
    }
    catch (...) {
        bEnc.Clear();
        ss = NTE_FAIL;
    }

    if (hKeyMS)
    {
        NCryptFreeObject(hKeyMS);
    }

    if (hProviderMS)
    {
        NCryptFreeObject(hProviderMS);
    }

    return ss;
}
