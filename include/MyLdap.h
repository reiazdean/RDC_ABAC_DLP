#pragma once
#include <mutex>
#include <string>
//http://msdn.microsoft.com/en-us/library/dd293575.aspx
//search filters
//http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
#include <stdint.h>
#ifdef OS_WIN32
#include <winldap.h>
#include <winber.h>
#else
extern "C" {
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <lber.h>
}
#endif
#include "Buffer.h"

using std::string;
using std::mutex;

namespace ReiazDean {
    //*************************************************
    //
    //CLASS _CLdap
    //
    //*************************************************
    class CLdap {
    protected:
    public:
        //************   Cons/Destruction   ***********
        CLdap();
        CLdap(const CLdap&) = delete;
        CLdap(CLdap&&) = delete;
        virtual ~CLdap();

        //************   Class Attributes   ****************
    private:
        static mutex  mutexVar;
        static CLdap  TheCLdap;
    public:
        
        //************   Class Methods   *******************
    private:
    protected:
        static bool ParseURI(const char* cdp, Buffer& host, Buffer& base, Buffer& filter, Buffer& attr, ULONG& scope);
    public:

        static CLdap& GetInstance() {
            return TheCLdap;
        };
        static bool ProcessURI(char* cdp, Buffer& bOut);
        //************ Instance Attributes  ****************
    private:
    protected:
        LDAP*                           m_pLdapConnection;
        Buffer                          m_Host;
        Buffer                          m_QDN;
        bool                            m_bConnected;
        bool                            m_bAuthenticated;
        bool                            m_bIsSSLEnabled;
    public:

        //************ Instance Methods  ****************
    private:
    protected:
        virtual bool                    FindGroups(Buffer& bUPN, Mandatory_AC &mac);
        virtual bool                    FindUser(Buffer& bUPN, Mandatory_AC &mac);
        virtual bool                    GetGroupDescription(const char* pcDN, Buffer& bGroup);
    public:
        CLdap&                          operator=(const CLdap& original) = delete;
        CLdap&                          operator=(CLdap&& original) = delete;
        virtual bool                    Connect(Buffer& bHostURL);
        virtual bool                    Connect();
        virtual bool                    Bind(Buffer& bUserDN, Buffer& bPwd, Buffer& bFQDN);
        virtual bool                    Bind(Buffer& bFQDN);
        virtual bool                    Bind();
        virtual bool                    Disconnect();
        bool                            Reconnect();
        char*                           GetQDN() { return (char*)m_QDN; };
        char*                           GetHost() { return (char*)m_Host; };
        bool                            IsConnected() { return m_bConnected; };
        bool                            IsAuthenticated() { return m_bAuthenticated; };
        bool                            IsUserMemberOf(Buffer& bUPN, char* pcGroup);
        bool                            GetAccessControlForUser(Buffer& bUPN, Mandatory_AC &mac);
        bool                            GetMLSDescriptions(Buffer& b);
        bool                            GetMCSDescriptions(Buffer& b);
        bool                            GetAttributes(Buffer& bUPN, Buffer& bAttributes);
        bool                            DownloadCertURI(char* cdp, Buffer& bCRL);
        bool                            IsComputerInDomain(const char* bComp, bool& bSandboxed, uint16_t& mls);
        bool                            KeepAlive();
    };
}

