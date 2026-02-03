#pragma once
#include <string>
#include <mutex>
#include <stdint.h>
#include "Buffer.h"

using std::mutex;
using std::wstring;

#define ALG_KYBER 1
#define ALG_DILITHIUM 2

//*************************************************
//
//CLASS    LatticeKeyPair    
//
//*************************************************
namespace ReiazDean {
    class LatticeKeyPair {
        //************Cons/Destruction***********
    private:
    protected:
    public:
        LatticeKeyPair() { m_Alg = 0; };
        LatticeKeyPair(const LatticeKeyPair&) = delete;
        LatticeKeyPair(LatticeKeyPair&&) = delete;
        virtual ~LatticeKeyPair() {};

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
        Buffer                        m_PubKey;
        Buffer                        m_PrivKey;
        uint32_t                      m_Alg;
        mutex                         m_Mutex;

        //************Instance Methods****************
    private:
    protected:
    public:
        LatticeKeyPair&               operator=(const LatticeKeyPair& original) = delete;
        LatticeKeyPair&               operator=(LatticeKeyPair&& original) = delete;
        virtual int32_t               Create() = 0;
        bool                          ImportPublic(uint8_t* pcPubKey, size_t szPubKey);
        uint8_t*                      GetPublicKey() { return (uint8_t*)m_PubKey; };
        uint32_t                      GetPublicKeySize() { return m_PubKey.Size(); };
        uint32_t                      GetAlg() { return m_Alg; };
        virtual uint8_t*              GetSecret() { return nullptr; };
        virtual uint32_t              GetSecretSize() { return 0; };
        virtual uint32_t              Sign(const Buffer& bData, Buffer& bSignature);
        virtual bool                  Verify(const Buffer& bData, const Buffer bSignature);
        virtual int8_t                WrapRandomAESkey(uint8_t* pcPubKey, int32_t szPubKey, Buffer& bWrappedKey);
        virtual int8_t                UnwrapAESKey(Buffer bWrappedKey);
    };
}
