/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "Utils.h"
#include <Windows.h>
#include <wtsapi32.h>
#include <dpapi.h>
#include "NdacConfig.h"
#include "KSPkey.h"
#include "SequenceReader.h"
#include "MyKeyManager.h"

using namespace ReiazDean;

extern Buffer* pPasswordBuffer;

BOOL
base64Encode(
    uint8_t* pbDataIn,
    size_t dwLenIn,
    Buffer& bPEM);

uint32_t
MyKeyManager::CountKeys()
{
    uint32_t numKeys = 0;
    Buffer bKeyNames;
    std::vector<WCHAR*> pieces;
    uint32_t count = 0;
    uint32_t i = 0;
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);

    KSPkey::EnumKeys((WCHAR*)bKSPw, bKeyNames);

    count = splitStringW((WCHAR*)bKeyNames, (WCHAR*)L"\n", pieces);
    for (i = 0; i < count; i++) {
        if (wcsstr((WCHAR*)pieces.at(i), (WCHAR*)MY_SERVER_KSP_KEY_NAME)) {
            numKeys++;
        }
    }

    return numKeys;
}

uint32_t
MyKeyManager::ExportKeys(Buffer& bOut, uint8_t* pcPwd, uint32_t pwdSz)
{
    Buffer bKeys;
    uint32_t numKeys = 0;
    Buffer bKeyNames;
    std::vector<WCHAR*> pieces;
    uint32_t count = 0;
    uint32_t i = 0;
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);

    KSPkey::EnumKeys((WCHAR*)bKSPw, bKeyNames);

    count = splitStringW((WCHAR*)bKeyNames, (WCHAR*)L"\n", pieces);
    for (i = 0; i < count; i++) {
        if (wcsstr((WCHAR*)pieces.at(i), (WCHAR*)MY_SERVER_KSP_KEY_NAME)) {
            Buffer bDerived;
            Buffer bKey;
            if (TheMyKeyManager.DeriveRootKey((WCHAR*)pieces.at(i), bDerived)) {
                bKey.Append((void*)pieces.at(i), wcslen((WCHAR*)pieces.at(i)) * sizeof(WCHAR));
                bKey.NullTerminate_w();
                bKey.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
                bDerived.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
                bKey.Append(bDerived);
                bKey.ASN1Wrap(CONSTRUCTED_SEQUENCE);
                bKeys.Append(bKey);
                numKeys++;
                //LogBinary(stdout, (uint8_t*)"\nkey:\n", (uint8_t*)bKey, bKey.Size());
            }
        }
    }

    if (numKeys > 0) {
        Buffer bHash;
        Buffer bEnc;
        Sha384(pcPwd, pwdSz, bHash);
        bKeys.ASN1Wrap(CONSTRUCTED_SEQUENCE);
        if (AES_CBC_Encrypt((uint8_t*)bHash, (uint8_t*)bHash + AES_256_KEY_SZ, (uint8_t*)bKeys, bKeys.Size(), bEnc) > 0) {
            if (base64Encode((uint8_t*)bEnc, bEnc.Size(), bOut)) {
                return numKeys;
            }
        }
    }

    return 0;
}

MyKeyManager::MyKeyManager()
{
    myKeyIndex = 0;
}

MyKeyManager::~MyKeyManager()
{
}

bool
MyKeyManager::DeriveRootKey(WCHAR* pwcKeyName, Buffer& bDerived)
{
    char cData[] = "ReiazAnnMarieHannahAayeshaFarrahDean";
    Buffer bHash;
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);
    KSPkey ksp((WCHAR*)bKSPw);

    if (ERROR_SUCCESS != ksp.OpenKey(pwcKeyName, 0)) {
        return false;
    }

    Sha384((uint8_t*)cData, (uint32_t)strlen(cData), bHash);
    if (ERROR_SUCCESS != ksp.SignHash((uint8_t*)bHash, bHash.Size(), bDerived)) {
        return false;
    }

    return true;
}

bool
MyKeyManager::LoadKeys()
{
    Buffer bKeyNames;
    std::vector<WCHAR*> pieces;
    uint32_t count;
    uint32_t i;
    NdacServerConfig& nc = NdacServerConfig::GetInstance();

    std::unique_lock<std::mutex> mlock(myMutex);
    try {
        Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);
        myDerivedSymmetricKeys.clear();
        KSPkey::EnumKeys((WCHAR*)bKSPw, bKeyNames);

        count = splitStringW((WCHAR*)bKeyNames, (WCHAR*)L"\n", pieces);
        for (i = 0; i < count; i++) {
            if (wcsstr((WCHAR*)pieces.at(i), (WCHAR*)MY_SERVER_KSP_KEY_NAME)) {
                Buffer bDerived;
                if (DeriveRootKey(pieces.at(i), bDerived)) {
                    Buffer bKey;
                    bKey.Append((void*)pieces.at(i), wcslen(pieces.at(i)) * sizeof(WCHAR));
                    bKey.NullTerminate_w();
                    myDerivedSymmetricKeys.push_back(std::pair<Buffer, Buffer>(bKey, bDerived));
                }
            }
        }
    }
    catch (...) {
        myDerivedSymmetricKeys.clear();
        return false;
    }

    return true;
}

bool
MyKeyManager::WrapDerivedKeys(Buffer& bWrapped)
{
    std::unique_lock<std::mutex> mlock(myMutex);
    try {
        for (const auto& p : myDerivedSymmetricKeys) {
            Buffer bPair;
            Buffer bKey = p.first;
            Buffer bDerived = p.second;
            bKey.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bDerived.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bPair.Append(bKey);
            bPair.Append(bDerived);
            bPair.ASN1Wrap(CONSTRUCTED_SEQUENCE);
            bWrapped.Append(bPair);
        }
        bWrapped.ASN1Wrap(CONSTRUCTED_SEQUENCE);
    }
    catch (...) {
        bWrapped.Clear();
        return false;
    }

    return true;
}

bool
MyKeyManager::UnwrapDerivedKeys(Buffer bWrapped)
{
    SequenceReaderX seq;
    std::unique_lock<std::mutex> mlock(myMutex);
    try {
        if (seq.Initilaize(bWrapped)) {
            int idx = 0;
            Buffer bVal;
            while (seq.getElementAt(idx++, bVal)) {
                SequenceReaderX seq2;
                if (seq2.Initilaize(bVal)) {
                    Buffer bKey, bDerived;
                    if (seq2.getValueAt(0, bKey) && seq2.getValueAt(1, bDerived)) {
                        myDerivedSymmetricKeys.push_back(std::pair<Buffer, Buffer>(bKey, bDerived));
                    }
                }
                bVal.Clear();
            }
        }
    }
    catch (...) {
        myDerivedSymmetricKeys.clear();
        return false;
    }

    return true;
}

bool
MyKeyManager::GetDerivedKey(WCHAR* pwcKeyName, Buffer& bDerived)
{
    std::unique_lock<std::mutex> mlock(myMutex);
    for (const auto& p : myDerivedSymmetricKeys) {
        Buffer bKey = p.first;
        if (wcscmp((WCHAR*)bKey, pwcKeyName) == 0) {
            bDerived = p.second;
            return true;
        }
    }

    return false;
}


bool
MyKeyManager::TestKeyBlockSize(Buffer& k) {
    bool     bRc = false;
    char     test[] = "abcdefghijklmnopqrstuvwxyz01234";//size 31 + NULL = 32
    Buffer   bEnc;
    int32_t  len = sizeof(test);

    len = AES_CBC_Encrypt((uint8_t*)k, (uint8_t*)k, (uint8_t*)test, len, bEnc);
    if (len > 0) {
        Buffer bPlain;
        len = AES_CBC_Decrypt((uint8_t*)k, (uint8_t*)k, (uint8_t*)bEnc, bEnc.Size(), bPlain);
        if (memcmp((void*)bPlain, test, sizeof(test)) == 0) {
            bRc = true;
        }
    }

    return bRc;
}

bool
MyKeyManager::TestKeyNonBlockSize(Buffer& k) {
    bool     bRc = false;
    char     test[] = "abcdefghijklmnopqrstuvwxyz";//size 26 + NULL = 27
    Buffer   bEnc;
    int32_t  len = sizeof(test);

    len = AES_CBC_Encrypt((uint8_t*)k, (uint8_t*)k, (uint8_t*)test, len, bEnc);
    if (len > 0) {
        Buffer bPlain;
        len = AES_CBC_Decrypt((uint8_t*)k, (uint8_t*)k, (uint8_t*)bEnc, bEnc.Size(), bPlain);
        if (memcmp((void*)bPlain, test, sizeof(test)) == 0) {
            bRc = true;
        }
    }

    return bRc;
}

bool
MyKeyManager::TestKey(Buffer& k) {
    return TestKeyBlockSize(k) && TestKeyNonBlockSize(k);
}

bool
MyKeyManager::CalculateDecryptionKey(WCHAR* pwcHSMkey, Mandatory_AC& mac, Buffer& bCalculatedKey)
{
    Buffer bDerived;
    
    if (GetDerivedKey(pwcHSMkey, bDerived)) {//MY_SERVER_KSP_KEY_NAME
        bDerived.Append((void*)&mac, sizeof(mac.mls_level) + sizeof(mac.mcs));
        Sha384((uint8_t*)bDerived, bDerived.Size(), bCalculatedKey);
        return TestKey(bCalculatedKey);
    }

    return false;
}

bool
MyKeyManager::CalculateEncryptionKey(Mandatory_AC& mac, Buffer& bCalculatedKey, Buffer& bKeyName)
{
    Buffer bDerived;

    std::unique_lock<std::mutex> mlock(myMutex);

    bKeyName = myDerivedSymmetricKeys.at(myKeyIndex).first;
    bKeyName.NullTerminate_w();
    bDerived = myDerivedSymmetricKeys.at(myKeyIndex).second;
    
    bDerived.Append((void*)&mac, sizeof(mac.mls_level) + sizeof(mac.mcs));
    Sha384((uint8_t*)bDerived, bDerived.Size(), bCalculatedKey);
    
    myKeyIndex++;
    if (myKeyIndex >= myDerivedSymmetricKeys.size()) {
        myKeyIndex = 0;
    }

    return TestKey(bCalculatedKey);;
}
