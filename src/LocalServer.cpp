/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#ifndef OS_WIN32
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <sys/un.h>
#include <syslog.h>
#endif
#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include "Utils.h"
#include "threadPool.h"
#include "LocalServer.h"
#include "ECKeyPair.h"
#include "TLSServerContext.h"
#include "TLSClientContext.h"
#include "MyLdap.h"
#include "NdacConfig.h"
#include "MyKeyManager.h"
#include "KSPkey.h"
#include "rdc_events.h"
#include "DilithiumKeyPair.h"
#include "clusterServiceManager.h"
#include "SnmpTrap.h"

using namespace ReiazDean;
using std::string;

extern void
ServiceReportEvent(
    LPTSTR szMessage,
    WORD dwCategory,
    WORD dwType,
    DWORD dwErr);
extern bool ValidateFolders();

extern HANDLE ghSvcStopEvent;

LocalServer* LocalServer::serverInstance = NULL;
mutex LocalServer::myMutex;
condition_variable LocalServer::myCondVar;
std::atomic<bool> LocalServer::Stopped = false;
std::atomic<int> LocalServer::WorkersNotDone = 0;
SOCKET connection_socket = 0;

void LocalServer::WorkerListen()
{
    WorkersNotDone++;
}

void LocalServer::DoneWorking()
{
    WorkersNotDone--;
}

void* LocalServer::LdapKeepAlive(void* arg)
{
    time_t          then;
    time(&then);
    CLdap& pMyLdap = CLdap::GetInstance();
    WorkersNotDone++;
    while (!Stopped) {
        time_t now;
        time(&now);
        std::unique_lock<std::mutex> mlock(myMutex);
        if (difftime(now, then) > 60.0f) {
            if (!pMyLdap.KeepAlive()) {
                SnmpTrap trap((char*)"AD LDAP connection lost!", (uint32_t)strlen("AD LDAP connection lost!"));
                if (pMyLdap.Reconnect()) {
                    SnmpTrap trap((char*)"AD LDAP connection resumed!", (uint32_t)strlen("AD LDAP connection resumed!"));
                }
            }
            then = now;
        }
        myCondVar.wait_for(mlock, std::chrono::seconds(5));
    }

    WorkersNotDone--;

    return 0;
}

void* LocalServer::ClusterSecretsPoller(void* arg)
{
    ClusterServiceManager& csm = ClusterServiceManager::GetInstance();
    Buffer bSecrets;
    time_t then;
    
    WorkersNotDone++;
    time(&then);
    do {
        time_t now;
        time(&now);
        std::unique_lock<std::mutex> mlock(myMutex);
        if (LocalServer::serverInstance->mPwdFutureSatisfied) {
            break;
        }
        else if (difftime(now, then) < 2.0f) {
            bSecrets.Clear();
            if (csm.PollMembersForSecrets(bSecrets)) {
                break;
            }
        }
        else if (difftime(now, then) > 60.0f) {
            bSecrets.Clear();
            if (csm.PollMembersForSecrets(bSecrets)) {
                break;
            }
            then = now;
        }
        myCondVar.wait_for(mlock, std::chrono::seconds(5));
    } while (!Stopped);

    if (bSecrets.Size() > 0) {
        LocalServer::serverInstance->HandleSecrets(bSecrets);
    }
    WorkersNotDone--;
    return 0;
}

/******************************************************************************************
Function Name:		Constructor/Destructor.
Parameters:
Description:
*******************************************************************************************/
LocalServer::LocalServer()
{
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();
    Buffer bNeedsPwd = scfg.GetValue(KSP_NEEDS_PASSWORD);

    LocalServer::serverInstance = this;
    mPwdFutureSatisfied = false;
    mPrivKeyPassword.Clear();
    if (bNeedsPwd.Size() == 0) {
        exit(-1);
    }

    if (strcmp((char*)bNeedsPwd, (char*)"yes") == 0) {
        DoLocalServer();
    }
    else {
        StartTLS();
    }
}

LocalServer::LocalServer(ServiceType type) : LocalServer()
{
    mServiceType = type;
}

LocalServer::~LocalServer()
{
    while (WorkersNotDone > 0) {
        std::this_thread::yield();
    }
}

/******************************************************************************************
Function Name:		StartTLS
Parameters:
Description:
*******************************************************************************************/
bool LocalServer::StartTLS()
{
    MyKeyManager& mykey = MyKeyManager::GetInstance();
    CLdap& mCLdap = CLdap::GetInstance();
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();
    SECURITY_STATUS ss = NTE_FAIL;
    Buffer bKSPw = scfg.GetValueW(KEY_STORAGE_PROVIDER);
    
    try {
        Buffer bSecrets;
        KSPkey ksp((WCHAR*)bKSPw);
        if (ERROR_SUCCESS != ksp.OpenKey((WCHAR*)MY_SERVER_KSP_KEY_NAME, 0)) {
            return false;
        }
        
        if (LoadSecrets(ksp, bSecrets)) {
            SequenceReaderX seq;
            ClusterServiceManager& csm = ClusterServiceManager::GetInstance();
            csm.SetSecrets(bSecrets);
            
            if (seq.Initilaize(bSecrets)) {
                seq.getValueAt(0, mPrivKeyPassword);
                if (mPrivKeyPassword.Size() > 0) {
                    mPwdFutureSatisfied = true;
                    mPrivKeyPassword.LockPages();
                    threadPool::queueThread((void*)LocalServer::LaunchService, (void*)NULL);
                    return true;
                }
            }
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

/******************************************************************************************
Function Name:		LaunchService
Parameters:
Description:
*******************************************************************************************/
void* LocalServer::LaunchService(void* arg)
{
    int8_t bMsg[256];
    CLdap& ldp = CLdap::GetInstance();
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    size_t             sz = 0;
    int32_t            szOut = 0;
    bool               bound = false;
    bool               connected = false;
    Buffer             port = nc.GetValue(TLS_PORT_STRING);

    connected = ldp.Connect();
    ServiceReportEvent(
        [&]() mutable {
            stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s connecting to AD host: %s", (connected ? (char*)"Success" : (char*)"Failed"), ldp.GetHost());
            return (char*)bMsg;
        }(),
            LOCAL_SERVICE_CATEGORY,
            (connected ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_ERROR),
            (connected ? MSG_SUCCESS : MSG_FAILED));

    if (connected) {
#ifdef _DEBUG
        printf("about to bind\n");
#endif
        bound = ldp.Bind();

        ServiceReportEvent(
            [&]() mutable {
                stringWrite(bMsg, sizeof(bMsg), (int8_t*)"%s binding to AD host: %s", (bound ? (char*)"Success" : (char*)"Failed"), ldp.GetHost());
                return (char*)bMsg;
            }(),
                LOCAL_SERVICE_CATEGORY,
                (bound ? STATUS_SEVERITY_SUCCESS : STATUS_SEVERITY_ERROR),
                (bound ? MSG_SUCCESS : MSG_FAILED));

        if (bound) {
            if (ValidateFolders()) {
                int iPort = atoi((char*)port);
                threadPool::queueThread((void*)LocalServer::LdapKeepAlive, (void*)NULL);
                ServiceReportEvent((LPTSTR)"Success validating document storage folders!", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_SUCCESS, MSG_SUCCESS);
                LocalServer::serverInstance->TlsServerSetup(iPort);
            }
            else {
                ServiceReportEvent((LPTSTR)"Failed to validate document storage folders!", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_ERROR, MSG_FAILED);
            }
        }
    }

    return 0;
}

/******************************************************************************************
Function Name:		tlsServerSetup
Parameters:
Description:
*******************************************************************************************/
void LocalServer::TlsServerSetup(int sslPort)
{
    mWsSock = OpenServerInetSocket(sslPort);
    if (mWsSock == 0)
    {
        return;
    }

    TLSServerContext::DoTlsServer(mWsSock, mPrivKeyPassword);
}

bool LocalServer::HandleSecrets(Buffer& bSecrets)
{
    ClusterServiceManager& csm = ClusterServiceManager::GetInstance();
    MyKeyManager& mykey = MyKeyManager::GetInstance();
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();

    if (bSecrets.Size() == 0) {
        return false;
    }

    std::unique_lock<std::mutex> mlock(myMutex);
    if (!mPwdFutureSatisfied) {
        Buffer bPrivKeyPwd, bKeys, bSnpmPriv, bSnmpAuth;
        SequenceReaderX seq;

        if (!seq.Initilaize(bSecrets)) {
            return false;
        }
        else {
            seq.getValueAt(0, bPrivKeyPwd);
            if (bPrivKeyPwd.Size() == 0) {
                return false;
            }
            
            seq.getValueAt(1, bSnpmPriv);
            if (bSnpmPriv.Size() == 0) {
                return false;
            }

            seq.getValueAt(2, bSnmpAuth);
            if (bSnmpAuth.Size() == 0) {
                return false;
            }

            seq.getElementAt(3, bKeys);
            if (bKeys.Size() == 0) {
                return false;
            }
        }

        if (!mykey.UnwrapDerivedKeys(bKeys)) {
            return false;
        }

        SnmpTrap::SetPwds(bSnpmPriv, bSnmpAuth);
        //open Dilithium
        try {
            DilithiumKeyPair& dpk = TLSContext::GetDilithium();
            Buffer bSKfile = scfg.GetValue(DILITHIUM_SECRET_FILE);
            Buffer bPKfile = scfg.GetValue(DILITHIUM_PUBLIC_FILE);
            if (!dpk.Open((char*)bSKfile, (char*)bPKfile, (char*)bPrivKeyPwd)) {
                char cMsg[] = "Local Service TLS failed to start due to missing Dilithium key pair.";
                SnmpTrap trap(cMsg, (uint32_t)strlen(cMsg));
                ServiceReportEvent(cMsg, LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_SUCCESS, MSG_SUCCESS);
                return false;
            }
        }
        catch (...) {
            return false;
        }

        threadPool::queueThread((void*)LocalServer::LaunchService, (void*)NULL);
        csm.SetSecrets(bSecrets);
        mPrivKeyPassword = bPrivKeyPwd;
        mPrivKeyPassword.LockPages();
        mPwdFutureSatisfied = true;

        ServiceReportEvent((TCHAR*)"Local Service TLS started.", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_SUCCESS, MSG_SUCCESS);
        {
            SnmpTrap trap((char*)"Local Service TLS started.", (uint32_t)strlen("Local Service TLS started."));
        }
    }

    return true;
}

int LocalServer::DoLocalServer()
{
    ECKeyPair   ecdh;
    uint8_t* pcOSpubKey = nullptr;
    uint32_t    szOSpub = 0;
    int         ret;
    int         result;

    connection_socket = OpenUnixSocket(true);
    if (connection_socket == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ret = listen(connection_socket, 1);
    if (ret == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    ServiceReportEvent((TCHAR*)"Local Service listening.", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_SUCCESS, MSG_SUCCESS);

    threadPool::queueThread((void*)LocalServer::ClusterSecretsPoller, (void*)NULL);

    /* This is the main loop for handling connections. */
    while (!Stopped) {
        SOCKET data_socket = 0;
        int r;
        r = Select(connection_socket, 0, 500000, true);
        if (r == 0) {
            continue;
        }

        /* Wait for incoming connection. */
        data_socket = accept(connection_socket, NULL, NULL);
        if (data_socket == -1) {
            continue;
        }

        result = 0;
        SetToNotBlock(data_socket);
        while (1) {
            Buffer b;
            Buffer bSecrets;
            CommandHeader* pch = nullptr;
            MyKeyManager& pMyKeyManager = MyKeyManager::GetInstance();

            r = Select(data_socket, 0, 0, true);
            if (r != 1) {
                break;
            }

            ret = NonBlockingRead(data_socket, b);
            if (ret < sizeof(CommandHeader)) {
                break;
            }

            pch = (CommandHeader*)b;
            switch (pch->command) {
            case Commands::CMD_EXCHANGE_ECDH_KEYS:
                pcOSpubKey = m_ECKeyPair.GetPublicKey();
                szOSpub = m_ECKeyPair.GetPublicKeySize();
                m_ECKeyPair.DeriveAESkey((uint8_t*)b + sizeof(CommandHeader), pch->szData);
                b.Clear();
                b.Append(pcOSpubKey, szOSpub);
                ret = NonBlockingWrite(data_socket, b);
                break;
            case Commands::CMD_SEND_TLS_PK_PASSWD:
                m_ECKeyPair.AES_Decrypt((uint8_t*)b + sizeof(CommandHeader), pch->szData, bSecrets);
                HandleSecrets(bSecrets);
                break;
            case Commands::CMD_RELOAD_ROOT_KEYS:
                pMyKeyManager.LoadKeys();
                break;
            case Commands::CMD_STOP_LOCAL_SERVICE:
                Stopped = true;
                ServiceReportEvent((TCHAR*)"Local Service stopping.", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_SUCCESS, MSG_SUCCESS);
                break;
            default:
                break;
            }
        }
        CloseSocket(data_socket);
    }

    CloseUnixSocket(connection_socket);
#ifdef OS_WIN32
    SetEvent(ghSvcStopEvent);
#endif

    ServiceReportEvent((TCHAR*)"Local Service has been gracefully shutdown.", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_SUCCESS, MSG_SUCCESS);

    return EXIT_SUCCESS;
}
