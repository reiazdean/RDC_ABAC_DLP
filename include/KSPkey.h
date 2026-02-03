#pragma once
#include <string>
#include <mutex>
#include <stdint.h>
#include "Utils.h"

using std::mutex;
using std::wstring;

//*************************************************
//
//CLASS    KSPkey    
//
//*************************************************
namespace ReiazDean {
    class KSPkey {
        //************Cons/Destruction***********
    private:
    protected:
    public:
        KSPkey();
        KSPkey(WCHAR* pwcProvider);
        KSPkey(const KSPkey&) = delete;
        KSPkey(KSPkey&&) = delete;
        virtual ~KSPkey();

        //************Class Attributes  ****************
    private:
        static mutex m_Mutex;
        static Buffer Password;
    protected:
    public:

        //************Class Methods*******************
    private:
    protected:
    public:
        static SECURITY_STATUS EnumProviders(Buffer& bProvs);
        static SECURITY_STATUS EnumKeys(WCHAR* pwcProvider, Buffer& bKeys);
        static SECURITY_STATUS Encrypt(WCHAR* pwcProvName, WCHAR* pwcKeyName, Buffer& bPlain, Buffer& bEnc);
        static Buffer& GetPassword() { return Password; };
    private:
    protected:
        NCryptAlgorithmName* m_alg;
        NCRYPT_PROV_HANDLE m_provH;
        NCRYPT_KEY_HANDLE m_keyH;

        //************Instance Methods****************
    private:
    protected:
    public:
        KSPkey& operator=(const KSPkey& original) = delete;
        KSPkey& operator=(KSPkey&& original) = delete;
        NCryptAlgorithmName* GetAlg() { return m_alg; };
        DWORD GetLength();

        SECURITY_STATUS CreateKey(WCHAR* pwcKeyName, DWORD dwSpec);
        SECURITY_STATUS OpenKey(WCHAR* pwcKeyName, DWORD dwSpec);
        SECURITY_STATUS OpenKeySilently(WCHAR* pwcKeyName, DWORD dwSpec, char* pcPin);
        SECURITY_STATUS DestroyKey(WCHAR* pwcKeyName);
        SECURITY_STATUS SetCertificate(Buffer& bCert);
        SECURITY_STATUS GetCertificate(Buffer& bCert);
        SECURITY_STATUS GetProperty(WCHAR* pwcProp, Buffer& bProp);
        SECURITY_STATUS SignHash(uint8_t* pcHash, int32_t szHash, Buffer& bSig);
        SECURITY_STATUS GetPublicKey(Buffer& bKey);
        SECURITY_STATUS Decrypt(uint8_t *ciphertext, int32_t len, Buffer& bPlain);
    };
}
