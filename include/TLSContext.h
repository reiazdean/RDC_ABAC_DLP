#pragma once
#include <mutex>
#include "KyberKeyPair.h"
#include "DilithiumKeyPair.h"
#include "RSAPublicKey.h"

using std::mutex;

namespace ReiazDean {
    //*************************************************
    //
    //CLASS TLSContext 
    //
    //*************************************************
    class TLSContext
    {
        //************   Cons/Destruction   ***********
    private:
    protected:
    public:
        TLSContext();
        TLSContext(const TLSContext&) = delete;
        TLSContext(TLSContext&&) = delete;
        virtual ~TLSContext();

        //************   Class Attributes   ****************
    private:
    protected:
        static DilithiumKeyPair s_DilithiumKeyPair;
        static std::mutex s_MutexVar;
        static condition_variable s_ConditionVar;
        static std::unique_ptr<RSAPublicKey> s_RSAPublicKeyCA;
    public:

        //************   Class Methods   *******************
    private:
    protected:
        static bool CreateRSAPublicKey(char* caCertBundle);
    public:
        static DilithiumKeyPair& GetDilithium() { return s_DilithiumKeyPair; };
        static bool VerifyCertWithBundle(char* pcBundleFile, const uint8_t* pcCertData, uint32_t szCertData);
        static bool VerifySignatureWithCA(char* pcBundleFile, uint8_t* hash, uint32_t szHash, uint8_t* signature, uint32_t szSignature);
        //************ Instance Attributes  ****************
    private:
    protected:
        std::atomic<SSL*> m_ssl;
        std::atomic<SOCKET> m_sock;
        KyberKeyPair      m_KyberKeyPair;
        uint8_t           m_nonce[16];
        //************ Instance Methods  ****************
    private:
    protected:
        int               ReadAppend(Buffer &b);
        void              Shutdown();
    public:
        TLSContext&       operator=(const TLSContext& original) = delete;
        TLSContext&       operator=(TLSContext&& original) = delete;
        //IO
        void              SetSock(SOCKET sock) { m_sock = sock; };
        int               DoNonBlockingRead(Buffer& b, int timeout = 0);
        int               DoNonBlockingReadEx(Buffer& b, int timeout = 0);
        int               DoNonBlockingWriteEx(char* pcData, int szData, int timeout = 0);
        int               DoNonBlockingWrite(Buffer& b, int timeout = 0);
        int               BlockingRead(Buffer& b, int size);
        int               BlockingWrite(Buffer& b, int size);
        virtual bool      ProtectPassword() = 0;
        virtual bool      GetCertPassword(Buffer &bPwd) = 0;
    };
}


