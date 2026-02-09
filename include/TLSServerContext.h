#pragma once
#include "x509class.h"
#include "ECKeyPair.h"
#include "TLSContext.h"

namespace ReiazDean {
    //*************************************************
    //
    //CLASS TLSServerContext 
    //
    //*************************************************
    class TLSServerContext : public TLSContext
    {
    //************   Cons/Destruction   ***********
    private:
        TLSServerContext();
        TLSServerContext(SOCKET sock);
    protected:
    public:
        TLSServerContext(const TLSServerContext&) = delete;
        TLSServerContext(TLSServerContext&&) = delete;
        virtual           ~TLSServerContext();

    //************   Class Attributes   ****************
    private:
        static ECKeyPair         s_ECKeyPair;
        static Buffer            s_PrivateKeyPassword;
        static vector<SOCKET>    s_ConectingSockets;
        static bool              s_Reserved;
        static SSL_CTX*          s_ctx;
    protected:
    public:

    //************   Class Methods   *******************
    private:
        static SSL_CTX* CreateContext();
    protected:
        static void       ServerListen(SOCKET sock);
        static void*      ServerAccept(void* args);
    public:
        static bool       DoTlsServer(SOCKET sock, Buffer& bPwd);
        static void       DeleteContext();
        

    //************ Instance Attributes  ****************
    private:
    protected:
        X509_NAME*        m_Issuer;
        X509_NAME*        m_Subject;
        Buffer            m_ClientDerCert;
        Buffer            m_ClientSignature;
        Buffer            m_UPN;
        Buffer            m_NodeNameOrIP;
        bool              m_IsNodeSecretValid;
        Certificate       m_ClientCertificate;

    //************ Instance Methods  ****************
    private:
        bool              ReadWrite();
        bool              StartSSL();
        void              DetermineNodeNameOrIP(SOCKET sock, bool bUseDNS);
        bool              ProcessCommandEx(Buffer& b);
        bool              ProcessCommand(Buffer& b);
        bool              ReadClientAttributes();
        bool              ParseClientCertAndSig(uint8_t* pcASN);
        bool              VerifyClientSignature(Buffer& b);
        bool              ExchangeKyber(Buffer& b);
        bool              SendNonce(Buffer& b);
        bool              SendSandboxState(Buffer& b);
        bool              SendSandboxScript(Buffer& b);
        bool              SendSecrets(Buffer& bRecvSend);
        bool              SendClusterMembers(Buffer& bRecvSend);
        bool              SendTimeStampSign(Buffer& bRecvSend);
        bool              SendEncryptionKey(Mandatory_AC& userMac, Buffer& b);
        bool              SendDecryptionKey(Mandatory_AC& userMac, Buffer& b);
        bool              SaveClassifiedDocument(Mandatory_AC& userMac, Buffer& b);
        bool              SendSwInstaller(Buffer& bRecvSend);
        bool              SendClassifiedDocument(Mandatory_AC& userMac, Buffer& b);
        bool              SendDeclassifiedDocument(Mandatory_AC& userMac, Buffer& b);
        bool              PublishClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend);
        bool              DecryptDeclassifiedFile(Mandatory_AC& userMac, wchar_t* pwcFname);
        bool              DeclassifyClassifiedDocument(Mandatory_AC& userMac, Buffer& bRecvSend);
        bool              VerifyClassifiedDocument(Mandatory_AC& userMac, Buffer& b);
        bool              SendDocumentTree(Mandatory_AC& userMac, Buffer& b);
        bool              SendDocumentNames(Mandatory_AC& userMac, Buffer& bRecvSend);
        bool              SendErrorResponse(ReiazDean::Responses resp, Buffer& bRecvSend);
        bool              ReceiveUserCertRequest(Buffer& b);
        bool              SendUserCertificate(Buffer& b);
        void              PrintStatus(char* pcOperation);
    protected:
    public:
        virtual bool      ProtectPassword();
        virtual bool      GetCertPassword(Buffer &bPwd);
        TLSServerContext& operator=(const TLSServerContext& original) = delete;
        TLSServerContext& operator=(TLSServerContext&& original) = delete;
    };
}


