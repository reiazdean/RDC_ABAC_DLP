#pragma once
#include <string>
#include <mutex>
#include <stdint.h>
#include "Utils.h"

using std::mutex;
using std::wstring;

//*************************************************
//
//CLASS    ECKeyPair    
//
//*************************************************
namespace ReiazDean {
    class ECKeyPair {
        //************Cons/Destruction***********
    private:
    protected:
    public:
        ECKeyPair();
        ECKeyPair(const ECKeyPair&) = delete;
        ECKeyPair(ECKeyPair&&) = delete;
        ECKeyPair(int alg);
        virtual                     ~ECKeyPair();

        //************Class Attributes  ****************
    private:
    protected:
    public:

        //************Class Methods*******************
    private:
    protected:
    public:

        //************Instance Attributes****************
    private:
    protected:
        int                           m_alg;
        EVP_PKEY*                     m_eckey;
        Buffer                        m_PubKeyBytes;
        Buffer                        m_Secret;
        mutex                         m_Mutex;

        //************Instance Methods****************
    private:
    protected:
        int32_t                       Create();
        void                          GetCoordinates();
        EVP_PKEY*                     ImportPubKey(uint8_t* pcPubKey, int32_t szPubKey, const char* alg);
        size_t                        CalculateSecret(EVP_PKEY* publicECkey);
    public:
        ECKeyPair&                    operator=(const ECKeyPair&) = delete;
        ECKeyPair&                    operator=(ECKeyPair&&) = delete;
        int                           GetAlg() { return m_alg; };
        int8_t                        SignHash(uint8_t* pcHash, int32_t szHash, uint8_t* pbOutput, int32_t cbOutput, int32_t *pcbResult);
        int8_t                        VerifySignature(uint8_t* pcHash, int32_t szHash, uint8_t* pbSig, int32_t cbSig);
        int8_t                        DeriveAESkey(uint8_t* pcPubKey, int32_t szPubKey);
        uint8_t*                      GetPublicKey() { return (uint8_t*)m_PubKeyBytes; };
        uint32_t                      GetPublicKeySize() { return m_PubKeyBytes.Size(); };
        uint32_t                      AES_Encrypt(uint8_t *plaintext, uint32_t len, Buffer& bEnc);
        uint32_t                      AES_Decrypt(uint8_t *ciphertext, uint32_t len, Buffer& bPlain);
        void                          LockPages();
    };
}
