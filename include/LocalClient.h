#pragma once
#include "LocalServer.h"
#include "ECKeyPair.h"

using std::string;
using std::vector;
using std::map;
using std::thread;
using std::mutex;
using std::condition_variable;

namespace ReiazDean {
    class LocalClient {
        //************   Cons/Destruction   ***************
    private:
    public:
        LocalClient();
        LocalClient(const LocalClient&) = delete;
        LocalClient(LocalClient&&) = delete;
        virtual ~LocalClient();

        //************   Class Attributes   ****************
    private:
    public:
        
        //************   Class Methods   *******************
    private:
    protected:
    public:

        //************ Instance Attributes  ****************
    private:
        SOCKET                          mUnixSock;
        ECKeyPair                       m_ECKeyPair;
        bool                            m_Established;
        mutex                           mMutex;
    public:

        //************ Instance Methods  *******************
    private:
        int                             ExchangeECDH();
        Responses                       SendToProxyPrivate(Buffer& bCmd, Buffer& b);
    public:
        LocalClient&                    operator=(const LocalClient& original) = delete;
        LocalClient&                    operator=(LocalClient&& original) = delete;
        int                             SendToLocal(Commands c, Buffer &b);
        Responses                       SendToProxy(Buffer& bCmd, Buffer& b);
        SOCKET                          GetSock() { return mUnixSock; };
        bool                            Established() { return m_Established; };
    };
}

