#pragma once
#include <string>
#include <mutex>
#include <stdint.h>
#include "Utils.h"
#include "TLSClientContext.h"
#include "TLSServerContext.h"

using std::wstring;
using std::vector;
using std::map;
using std::mutex;

namespace ReiazDean {
    class DocHandler {
        //************   Cons/Destruction   ***************
    private:
    public:
        DocHandler();
        DocHandler(const DocHandler&) = delete;
        DocHandler(DocHandler&&) = delete;
        virtual ~DocHandler();

        //************   Class Attributes   ****************
    private:
    public:

        //************   Class Methods   *******************
    private:
    protected:
    public:
        //************ Instance Attributes  ****************
    private:
        mutex                          m_Mutex;
        Buffer                         m_Name;
        Buffer                         m_Version;
        Buffer                         m_Label;
        Buffer                         m_Application;
        Buffer                         m_Certificate;
        Buffer                         m_UPN;
        Buffer                         m_Signature;
        Buffer                         m_SignatureOfSignature;
        Buffer                         m_MCS;
        uint16_t                       m_MLS;
        Buffer                         m_HsmKeyName;
        Buffer                         m_EncryptionKey;
        Buffer                         m_DecryptionKey;
        Buffer                         m_AuthResponse;
        FILE*                          m_FP;
        uint32_t                       m_EncryptedSz;
        uint32_t                       m_FileSz;
        bool                           m_Verified;
        HANDLE                         m_LockHandle;

    public:

        //************ Instance Methods  *******************
    private:
        bool                           getUPN();
        bool                           readHeader();
        bool                           readDocCertAndSig();    
        uint32_t                       wrapClientCertAndSig(Buffer& bHash, Buffer& bCertAndSig);
    public:
        DocHandler&                    operator=(const DocHandler& original) = delete;
        DocHandler&                    operator=(DocHandler&& original) = delete;
        HANDLE                         GetLockHandle() { return m_LockHandle; };
        void                           PrintOn(WCHAR* pwcBuf, uint32_t sz);
        char*                          GetApplication() { return (char*)m_Application; };
        bool                           OpenDocument(wchar_t* pcDocName, bool bLock = false);
        bool                           OpenUnprotectedDocument(wchar_t* pcDocName, bool bLock = false);
        bool                           DecryptVerify(FILE* fOut, std::shared_ptr<NotifyView> notifier = nullptr);
        bool                           PartialVerify();
        bool                           GetAuthRequest(AuthorizationRequest& ar);
        void                           SetAuthResponse(const AuthorizationResponse& ar);
        bool                           ProtectFile(wchar_t* sDocName, wchar_t* outDoc, wchar_t* sApp,
                                                   std::shared_ptr<NotifyView> notifier = nullptr);
        static Responses               ReceiveDocument(TLSContext& tls,
                                                       wchar_t* filename,
                                                       wchar_t* tempfname,
                                                       int32_t len,
                                                       std::shared_ptr<NotifyView> notifier = nullptr);
        static Responses               ProxyReceiveDocument(TLSContext& tls,
                                                            SOCKET sbSocket,
                                                            int32_t len,
                                                            WCHAR* pwcLocalName);
        static Responses               ProxySendLocalDocument(SOCKET sbSocket,
                                                              WCHAR* pwcLocalName);
        static Responses               ProxyReceiveSendDocument(TLSContext& tls,
                                                                SOCKET sbSocket,
                                                                int32_t len);
        static Responses               ReceiveDocumentFromProxy(SOCKET sock,
                                                                wchar_t* filename,
                                                                wchar_t* tempfname,
                                                                int32_t len,
                                                                std::shared_ptr<NotifyView> notifier = nullptr);
        Responses                      SendDocument(TLSContext& tls, std::shared_ptr<NotifyView> notifier = nullptr);
        Responses                      SendDocumentToProxy(SOCKET sbSock, std::shared_ptr<NotifyView> notifier);
        void                           Close();
    };
}

