#pragma once
#include <stdint.h>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>

#include "Utils.h"
#include "Buffer.h"
#include "ECKeyPair.h"

namespace ReiazDean {

    using std::string;
    using std::vector;
    using std::map;
    using std::thread;
    using std::mutex;
    using std::condition_variable;
    using std::function;
    using std::atomic;

    class LocalServer {
        //************   Cons/Destruction   ***************
    private:
        LocalServer();
    public:
        LocalServer(ServiceType type);
        LocalServer(const LocalServer&) = delete;
        LocalServer(LocalServer&&) = delete;
        virtual ~LocalServer();

        //************   Class Attributes   ****************
    private:
        static LocalServer* serverInstance;
        static mutex myMutex;
        static condition_variable myCondVar;
        static std::atomic<bool> Stopped;
        static std::atomic<int> WorkersNotDone;
    public:

        //************   Class Methods   *******************
    private:
        static void*                    LdapKeepAlive(void *arg);
        static void*                    ClusterSecretsPoller(void* arg);
        static void*                    LaunchService(void* arg);
    protected:
    public:
        static bool                     HasNotStopped() { return !Stopped; };
        static void                     Stop() { Stopped = true; };
        static void                     WorkerListen();
        static void                     DoneWorking();
       
        //************ Instance Attributes  ****************
    private:
        ServiceType                     mServiceType;
        SOCKET                          mWsSock;
        Buffer                          mPrivKeyPassword;
        bool                            mPwdFutureSatisfied;
        ECKeyPair                       m_ECKeyPair;
    public:

        //************ Instance Methods  *******************
    private:
        LocalServer&                    operator=(const LocalServer& original) = delete;
        LocalServer&                    operator=(LocalServer&& original) = delete;
        bool                            StartTLS();
        int                             DoLocalServer();
        void                            TlsServerSetup(int sslPort);
        bool                            HandleSecrets(Buffer& bSecrets);
    public:
    };
}

