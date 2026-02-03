/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "pch.h"
#include <windows.h>
#include <bcrypt.h>
#include "Buffer.h"
#include "KyberKeyPair.h"
#include "DilithiumKeyPair.h"
#include "Crystals.h"

using namespace ReiazDean;

MemoryPoolManager  Buffer::MyMemPoolManager;

static HINSTANCE g_hInstance;
static std::mutex s_mutexVar;
static std::vector<std::pair<uint64_t, std::shared_ptr<LatticeKeyPair>>> s_LatticeKeys;
static std::atomic<uint64_t> s_CurrentHandle = 0;

CRYSTALS_FUNCTION_TABLE CrystalsFunctionTable =
{
    0,
    CreateKyberKey,
    CreateDilithiumKey,
    DestroyKey,
    ExportPublicKey,
    ImportPublicKey,
    Sign,
    Verify,
    Wrap,
    Unwrap,
    GetSecret
};

double
secondsSinceNewyear()
{
    time_t		now;
    time_t		then;
    struct tm	start;
    double		seconds = 0.0;

    time(&now);
    localtime_s(&start, &now);

    start.tm_hour = 0;
    start.tm_min = 0;
    start.tm_sec = 0;
    start.tm_mon = 0;
    start.tm_mday = 1;
    then = mktime(&start);
    seconds = difftime(now, then);

    return seconds;
}

uint32_t
AES_CBC_Encrypt(
    const uint8_t* pucKey,
    const uint8_t* pucIV,
    const uint8_t* plaintext,
    uint32_t        len,
    Buffer& bEnc)
{
    bEnc.Clear();
    return 0;
}

uint32_t
AES_CBC_Decrypt(
    const uint8_t* pucKey,
    const uint8_t* pucIV,
    const uint8_t* ciphertext,
    uint32_t        len,
    Buffer& bPlain)
{
    bPlain.Clear();
    return 0;
}

uint8_t
saveToFile(
    int8_t* fname,
    int8_t* pcData,
    uint32_t szData)
{
    FILE* fp = NULL;
    uint8_t   bRc = 0;

    if (!fname || !pcData)
        goto done;

    fopen_s(&fp, (char*)fname, "wb");
    if (fp == NULL)
        goto done;

    if (fwrite(pcData, 1, szData, fp) == szData) {
        bRc = 1;
    }

done:

    if (fp)
        fclose(fp);

    return bRc;
}

int32_t
readFile(
    char* fname,
    Buffer& data)
{
    int32_t       ret = -1;
    FILE* fp = NULL;
    struct _stat     buf;

    ret = _stat((char*)fname, &buf);
    if (ret == 0) {
        fopen_s(&fp, (char*)fname, "rb");
    }

    try {
        ret = 0;
        data.Clear();
        if (fp) {
            Buffer b(buf.st_size);
            ret = buf.st_size;
            if (ret == fread((char*)b, 1, ret, fp)) {
                data.Append((void*)b, ret);
            }
            fclose(fp);
            fp = NULL;
        }
    }
    catch (...) {
        if (fp) {
            fclose(fp);
        }
        data.Clear();
        return 0;
    }

    return ret;
}

void
ReverseMemory(
    uint8_t* pbData,
    uint32_t szData)
{
    uint32_t      index;
    uint32_t      transposeIndex;
    uint8_t      bTemp;

    if (!pbData) {
        return;
    }

    for (index = 0; index < (szData / 2); index++)
    {
        transposeIndex = szData - (1 + index);

        bTemp = pbData[transposeIndex];
        pbData[transposeIndex] = pbData[index];
        pbData[index] = bTemp;
    }

    return;
}

BOOL Digest(uint8_t* in, uint32_t len, const wchar_t* algid, Buffer& hashB)
{
    ULONG status = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbData = 0;
    DWORD cbHash = 0;
    DWORD cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, algid, NULL, 0);
    if (status == 0) {
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    }

    if (status == 0) {
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    }

    if (pbHashObject) {
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (status == 0) {
            pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        }
    }
    
    if (pbHash) {
        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    }

    if (status == 0) {
        status = BCryptHashData(hHash, in, len, 0);
    }

    if (status == 0) {
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
    }

    if (status == 0) {
        hashB.Append(pbHash, cbHash);
    }

    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);

    if (hHash)
        BCryptDestroyHash(hHash);

    if (pbHashObject)
        HeapFree(GetProcessHeap(), 0, pbHashObject);

    if (pbHash)
        HeapFree(GetProcessHeap(), 0, pbHash);

    return (status == 0);
}

uint32_t
Sha384(
    uint8_t* in,
    uint32_t  len,
    Buffer& out)
{
    Digest(in, len, BCRYPT_SHA384_ALGORITHM, out);
    return out.Size();
}

uint32_t
Sha512(
    uint8_t* in,
    uint32_t  len,
    Buffer& out)
{
    Digest(in, len, BCRYPT_SHA512_ALGORITHM, out);
    return out.Size();
}

uint32_t
Sha256(
    uint8_t* in,
    uint32_t  len,
    Buffer& out)
{
    Digest(in, len, BCRYPT_SHA256_ALGORITHM, out);
    return out.Size();
}

FILE*
f_open_f(
    char* pcName,
    char* pcMode)
{
    FILE* fp = nullptr;
    fopen_s(&fp, pcName, pcMode);
    return fp;
}

static std::atomic<double> secs = secondsSinceNewyear();
int
RandomBytes(
    Buffer& bRand)
{
    secs = secs + secondsSinceNewyear();
    bRand.Clear();
    Sha384((uint8_t*)&secs, sizeof(double), bRand);

    return bRand.Size();
}

///////////////////////////////////////////////////////////////////////////////
//
// Dll entry
//
///////////////////////////////////////////////////////////////////////////////

BOOL
WINAPI
DllMain(
    HMODULE hInstDLL,
    DWORD dwReason,
    LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);
    g_hInstance = (HINSTANCE)hInstDLL;

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {

    }
    return TRUE;
}

/******************************************************************************
* GetCrystalsInterface
*******************************************************************************/
NTSTATUS
WINAPI
GetCrystalsInterface(__out  CRYSTALS_FUNCTION_TABLE** ppFunctionTable)
{
    *ppFunctionTable = &CrystalsFunctionTable;
    return ERROR_SUCCESS;
}

/******************************************************************************
* CreateKyberKey
*******************************************************************************/
SECURITY_STATUS
WINAPI
CreateKyberKey(
    __out uint64_t* handle_p)
{
    std::shared_ptr<KyberKeyPair> ptr_k = nullptr;
    if (!handle_p) {
        return ERROR_INVALID_DATA;
    }

    *handle_p = 0;
    ptr_k = std::make_shared<KyberKeyPair>();
    if (ptr_k) {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        *handle_p = max(++s_CurrentHandle, 1);
        ptr_k->Create();
        s_LatticeKeys.push_back(std::pair<uint64_t, std::shared_ptr<LatticeKeyPair>>(*handle_p, ptr_k));
    }
    
    return (*handle_p > 0) ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}

/******************************************************************************
* CreateDilithiumKey
*******************************************************************************/
SECURITY_STATUS
WINAPI
CreateDilithiumKey(
    __out uint64_t* handle_p)
{
    std::shared_ptr<DilithiumKeyPair> ptr_k = nullptr;
    if (!handle_p) {
        return ERROR_INVALID_DATA;
    }

    *handle_p = 0;
    ptr_k = std::make_shared<DilithiumKeyPair>();
    if (ptr_k) {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        *handle_p = max(++s_CurrentHandle, 1);
        ptr_k->Create();
        s_LatticeKeys.push_back(std::pair<uint64_t, std::shared_ptr<LatticeKeyPair>>(*handle_p, ptr_k));
    }

    return (*handle_p > 0) ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}

/******************************************************************************
* DestroyKey
*******************************************************************************/
SECURITY_STATUS
WINAPI
DestroyKey(
    __in uint64_t handle_p)
{
    bool found = false;
    std::vector<std::pair<uint64_t, std::shared_ptr<LatticeKeyPair>>> tmp_LatticeKeys;

    std::unique_lock<std::mutex> mlock(s_mutexVar);
    for (const auto& kp : s_LatticeKeys) {
        if (handle_p != kp.first) {
            tmp_LatticeKeys.push_back(kp);
        }
        else {
            found = true;
        }
    }
    s_LatticeKeys = tmp_LatticeKeys;

    return found ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
}

/******************************************************************************
* ExportPublicKey
*******************************************************************************/
SECURITY_STATUS
WINAPI
ExportPublicKey(
    __in uint64_t handle,
    __out uint8_t* bPublic_p,
    __out size_t* szPublic)
{
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;
    {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        for (const auto& kp : s_LatticeKeys) {
            if (handle == kp.first) {
                ptr = kp.second;
                break;
            }
        }
    }

    if (!ptr) {
        return ERROR_INVALID_HANDLE;
    }

    if (bPublic_p) {
        if (*szPublic < ptr->GetPublicKeySize()) {
            *szPublic = ptr->GetPublicKeySize();
            return ERROR_INSUFFICIENT_BUFFER;
        }
        else {
            *szPublic = ptr->GetPublicKeySize();
            memcpy(bPublic_p, ptr->GetPublicKey(), ptr->GetPublicKeySize());
        }
    }
    else {
        *szPublic = ptr->GetPublicKeySize();
    }

    return ERROR_SUCCESS;
}

/******************************************************************************
* ImportPublicKey
*******************************************************************************/
SECURITY_STATUS
WINAPI
ImportPublicKey(
    __out uint64_t* handle_p,
    __in uint32_t alg,
    __in uint8_t* bPublic,
    __in size_t szPublic)
{
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;

    if (!handle_p || !bPublic) {
        return ERROR_INVALID_DATA;
    }

    *handle_p = 0;

    if (alg == ALG_KYBER) {
        ptr = std::make_shared<KyberKeyPair>();
    }
    else if (alg == ALG_DILITHIUM) {
        ptr = std::make_shared<DilithiumKeyPair>();
    }
    else {
        return NTE_BAD_ALGID;
    }

    if (ptr) {
        if (ptr->ImportPublic(bPublic, szPublic)) {
            std::unique_lock<std::mutex> mlock(s_mutexVar);
            *handle_p = max(++s_CurrentHandle, 1);
            s_LatticeKeys.push_back(std::pair<uint64_t, std::shared_ptr<LatticeKeyPair>>(*handle_p, ptr));
        }
    }

    return (*handle_p > 0) ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}

/******************************************************************************
* Sigh
*******************************************************************************/
SECURITY_STATUS
WINAPI
Sign(
    __in uint64_t handle,
    __in uint8_t* bData,
    __in size_t szData,
    __out uint8_t* pbSig,
    __out size_t* szSig)
{
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;
    Buffer sigB;
    uint32_t sz = 0;
    Buffer dataB(bData, szData);

    {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        for (const auto& kp : s_LatticeKeys) {
            if (handle == kp.first) {
                ptr = kp.second;
                break;
            }
        }
    }

    if (!ptr) {
        return ERROR_INVALID_HANDLE;
    }

    if (!pbSig) {
        *szSig = 2484;
        return ERROR_SUCCESS;
    }

    if (ptr->GetAlg() != ALG_DILITHIUM) {
        return NTE_BAD_ALGID;
    }

    if (0 == ptr->Sign(dataB, sigB)) {
        return NTE_BAD_SIGNATURE;
    }

    if (*szSig < (size_t)sigB.Size()) {
        *szSig = sigB.Size();
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *szSig = sigB.Size();
    memcpy(pbSig, (uint8_t*)sigB, sigB.Size());

    return ERROR_SUCCESS;
}

/******************************************************************************
* Verify
*******************************************************************************/
SECURITY_STATUS
WINAPI
Verify(
    __in uint64_t handle,
    __in uint8_t* bData,
    __in size_t szData,
    __in uint8_t* bSig,
    __in size_t szSig)
{
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;
    Buffer sigB(bSig, szSig);
    Buffer dataB(bData, szData);

    {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        for (const auto& kp : s_LatticeKeys) {
            if (handle == kp.first) {
                ptr = kp.second;
                break;
            }
        }
    }

    if (!ptr) {
        return ERROR_INVALID_HANDLE;
    }
    
    if (ptr->GetAlg() != ALG_DILITHIUM) {
        return NTE_BAD_ALGID;
    }

    if (!ptr->Verify(dataB, sigB)) {
        return NTE_BAD_SIGNATURE;
    }

    return ERROR_SUCCESS;
}

/******************************************************************************
* Wrap
*******************************************************************************/
SECURITY_STATUS
WINAPI
Wrap(
    __in uint64_t handle,
    __out uint8_t* bWrapped,
    __out size_t* szWrapped)
{
    Buffer wrappedB;
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;
   
    {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        for (const auto& kp : s_LatticeKeys) {
            if (handle == kp.first) {
                ptr = kp.second;
                break;
            }
        }
    }

    if (!ptr) {
        return ERROR_INVALID_HANDLE;
    }

    if (ptr->GetAlg() != ALG_KYBER) {
        return NTE_BAD_ALGID;
    }

    if (ptr->WrapRandomAESkey(ptr->GetPublicKey(), ptr->GetPublicKeySize(), wrappedB) == 0) {
        return NTE_BAD_DATA;
    }

    if (!bWrapped) {
        *szWrapped = wrappedB.Size();
        return ERROR_SUCCESS;
    }

    if (*szWrapped < (size_t)wrappedB.Size()) {
        *szWrapped = wrappedB.Size();
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *szWrapped = wrappedB.Size();
    memcpy(bWrapped, (uint8_t*)wrappedB, wrappedB.Size());

    return ERROR_SUCCESS;
}

/******************************************************************************
* Unwrap
*******************************************************************************/
SECURITY_STATUS
WINAPI
Unwrap(
    __in uint64_t handle,
    __in uint8_t* bWrapped,
    __in size_t szWrapped)
{
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;

    {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        for (const auto& kp : s_LatticeKeys) {
            if (handle == kp.first) {
                ptr = kp.second;
                break;
            }
        }
    }

    if (!ptr) {
        return ERROR_INVALID_HANDLE;
    }

    if (ptr->GetAlg() != ALG_KYBER) {
        return NTE_BAD_ALGID;
    }

    {
        Buffer wrappedB(bWrapped, szWrapped);
        if (ptr->UnwrapAESKey(wrappedB) == 0) {
            return NTE_BAD_DATA;
        }
    }

    return ERROR_SUCCESS;
}

/******************************************************************************
* GetSecret
*******************************************************************************/
SECURITY_STATUS
WINAPI
GetSecret(
    __in uint64_t handle,
    __out uint8_t* bSecret,
    __out size_t* szSecret)
{
    std::shared_ptr<LatticeKeyPair> ptr = nullptr;

    {
        std::unique_lock<std::mutex> mlock(s_mutexVar);
        for (const auto& kp : s_LatticeKeys) {
            if (handle == kp.first) {
                ptr = kp.second;
                break;
            }
        }
    }

    if (!ptr) {
        return ERROR_INVALID_HANDLE;
    }

    if (ptr->GetAlg() != ALG_KYBER) {
        return NTE_BAD_ALGID;
    }

    if (!bSecret) {
        *szSecret = ptr->GetSecretSize();
        return ERROR_SUCCESS;
    }
    
    if (*szSecret < ptr->GetSecretSize()) {
        *szSecret = ptr->GetSecretSize();
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *szSecret = ptr->GetSecretSize();
    memcpy(bSecret, ptr->GetSecret(), ptr->GetSecretSize());

    return ERROR_SUCCESS;
}
