#pragma once
#include "x509class.h"
#include "TLSContext.h"
#include "ECKeyPair.h"

namespace ReiazDean {
    //*************************************************
    //
    //CLASS TLSClientContext 
    //
    //*************************************************
    class TLSClientContext : public TLSContext
    {
        //************   Cons/Destruction   ***********
    private:
    protected:
    public:
        TLSClientContext();
        TLSClientContext(const TLSClientContext&) = delete;
        TLSClientContext(TLSClientContext&&) = delete;
        virtual           ~TLSClientContext();

        //************   Class Attributes   ****************
    private:
        static SSL_CTX* s_ctx;
        static std::vector<std::pair<Buffer, Buffer>> s_Hosts2IpAdrs;
    protected:
    public:

        //************   Class Methods   *******************
    private:
        static SSL_CTX* CreateContext();
    protected:
    public:
        static void Finalize();
        static void Map(Buffer bHost, Buffer bIP);
        static bool GetIP(Buffer bHost, Buffer& bIP);
        static bool GetHostAddrMapping(Buffer bIn, Buffer& bOut);
#ifdef _DEBUG
        static void Test(int numThreads);
#endif

        //************ Instance Attributes  ****************
    private:
        Buffer            m_bHost;
        Buffer            m_serverNonce;
        Certificate       m_Certificate;
    protected:


        //************ Instance Methods  ****************
    private:
    protected:
        Responses         EstablishClient();
        Responses         ReadServerNonce();
        Responses         SignNodeSecretAndNonce(Buffer& b);
        Responses         ValidateNodeSecret();
        Responses         ExchangeKyber();
    public:
        TLSClientContext& operator=(const TLSClientContext& original) = delete;
        TLSClientContext& operator=(TLSClientContext&& original) = delete;
        int32_t           AES_Encrypt(uint8_t *plaintext, int32_t len, Buffer& bEnc);
        int32_t           AES_Decrypt(uint8_t *ciphertext, int32_t len, Buffer& bPlain);
        Responses         DoClientNoCert();
        Responses         PartiallyEstablishClient();
        Responses         FullyEstablishClient();
        Responses         DoClusterClientNoCert(char* pcMemberIP);
        Responses         EstablishClusterClient();
        Responses         ExecuteCommand(Buffer cmd, Buffer& resp);
        void              LockPages();
        void              EndConnection();
        bool              GetUPNSubjectAltName(Buffer& bOut) {
            return m_Certificate.GetUPNSubjectAltName(bOut);
        };
        virtual bool      ProtectPassword() {
            return true;
        };
        virtual bool      GetCertPassword(Buffer& bPwd) {
            return true;
        };
    };
}
