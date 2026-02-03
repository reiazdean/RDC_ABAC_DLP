#pragma once
#include <string>
#include <mutex>
#include <stdint.h>
#include "Buffer.h"
#include "LatticeKeyPair.h"

using std::mutex;
using std::wstring;

//*************************************************
//
//CLASS    KyberKeyPair    
//
//*************************************************
namespace ReiazDean {
    class KyberKeyPair : public LatticeKeyPair {
        //************Cons/Destruction***********
    private:
    protected:
    public:
        KyberKeyPair();
        KyberKeyPair(const KyberKeyPair&) = delete;
        KyberKeyPair(KyberKeyPair&&) = delete;
        virtual ~KyberKeyPair();

        //************Class Attributes  ****************
    private:
    protected:
    public:

        //************Class Methods*******************
    private:
    protected:
    public:
        static bool                   Test();

        //************Instance Attributes****************
    private:
    protected:
        Buffer                        m_Secret;
        
        //************Instance Methods****************
    private:
    protected:
    public:
        KyberKeyPair&                 operator=(const KyberKeyPair &original);
        KyberKeyPair&                 operator=(KyberKeyPair&& original) = delete;
        virtual int32_t               Create();
        virtual int8_t                WrapRandomAESkey(uint8_t* pcPubKey, int32_t szPubKey, Buffer& bWrappedKey);
        virtual int8_t                UnwrapAESKey(Buffer bWrappedKey);
        virtual uint8_t*              GetSecret() { return (uint8_t*)m_Secret; };
        virtual uint32_t              GetSecretSize() { return m_Secret.Size(); };
        uint32_t                      AES_Encrypt(uint8_t *plaintext, uint32_t len, Buffer& bEnc);
        uint32_t                      AES_Decrypt(uint8_t *ciphertext, uint32_t len, Buffer& bPlain);
        void                          LockPages();
    };
}
