/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <chrono>
#include "Utils.h"
#include "clusterClientManager.h"
#include "NdacConfig.h"
#include "OsslClientHelper.h"

using namespace ReiazDean;

void SetLocalStatus(WCHAR* pwcText, bool bAppend);
extern std::atomic<BOOL> ApplicationStopped;
extern std::atomic<int> NumWorkersRunning;

void* ClusterClientManager::ClusterClientRecoveryProc(void* arg)
{
    time_t then;
    time(&then);
    NumWorkersRunning++;
    try {
        vector<Buffer> tmp;
        while (!ApplicationStopped) {
            char* pcMbr = nullptr;
            time_t now;
            time(&now);

            if (difftime(now, then) >= 60.0f) {
                then = now;
                //Checking if any failed members have recovered.
                for (auto& mbr : tmp) {
                    TLSClientContext client;
                    if (client.DoClusterClientNoCert((char*)mbr) && client.PartiallyEstablishClient()) {
                        TheClusterClientManager.RecoverMember((char*)mbr);
                    }
                }

                //Checking for changes in cluster membership. Additionals or removals.
                if (TheClusterClientManager.m_Members.size() > 0) {
                    CommandHeader ch = { CMD_EXCHANGE_CLUSTER_MBRS, 0 };
                    Buffer mbr = TheClusterClientManager.m_Members.at(0);
                    TLSClientContext client;
                    condition_variable cv;
                    Buffer bCmd, bResp;
                    bCmd.Clear();
                    bCmd.Append((void*)&ch, sizeof(CommandHeader));
                    if (OsslClientHelper::QueueCommand(client, bCmd, mbr, bResp, cv)) {
                        std::unique_lock<std::mutex> mlock(TheClusterClientManager.m_MutexVar);
                        cv.wait(mlock);
                    }
                    if (bResp.Size() > sizeof(ResponseHeader)) {
                        ResponseHeader* prh = (ResponseHeader*)bResp;
                        char* pc = (char*)bResp + sizeof(ResponseHeader);
                        if (prh->response == RSP_SUCCESS) {
                            if (bResp.Size() == (sizeof(ResponseHeader) + prh->szData)) {
                                Buffer bMbrs;
                                bMbrs.Append((void*)pc, prh->szData);
                                TheClusterClientManager.UpdateMembers(bMbrs);
                            }
                        }
                    }
                }
            }

            {
                std::unique_lock<std::mutex> mlock(TheClusterClientManager.m_MutexVar);
                if (!ApplicationStopped) {
                    TheClusterClientManager.m_ConditionVar.wait_for(mlock, std::chrono::seconds(5));
                    tmp = TheClusterClientManager.m_FailedMembers;
                }
            }
        }
    }
    catch (...) {
        NumWorkersRunning--;
        return 0;
    }

    NumWorkersRunning--;
    return 0;
}

ClusterClientManager::ClusterClientManager() {
    m_Current = 0;
}

bool ClusterClientManager::Persist()
{
    try {
        Buffer bLocation;
        Buffer bMbrs;

        WhereTo(bLocation);
        if (bLocation.Size() == 0) {
            return false;
        }

        GetMembers(bMbrs);

        if (bMbrs.Size() > 0) {
            return (1 == saveToFile((int8_t*)bLocation, (int8_t*)bMbrs, (uint32_t)strlen((char*)bMbrs)));
        }
        else {
            return (1 == saveToFile((int8_t*)bLocation, (int8_t*)"\n", 1));
        }
    }
    catch (...) {
        return false;
    }
}

bool ClusterClientManager::WhereTo(Buffer& bLocation)
{
    try {
        NdacClientConfig& cfg = NdacClientConfig::GetInstance();
        bLocation.Clear();
        bLocation = cfg.GetValue(CLUSTER_MEMBERS_FILE);
        return true;
    }
    catch (...) {
        bLocation.Clear();
        return false;
    }
}

bool ClusterClientManager::WhereFrom(Buffer& bLocation)
{
    return WhereTo(bLocation);
}

void ClusterClientManager::UpdateMembers(Buffer& bMbrs)
{
    try {
        bool bModified = false;
        std::vector<Buffer> tmp;
        std::vector<char*> pieces;
        Buffer bTmp(bMbrs);
        splitStringA((char*)bTmp, (char*)"\r\n", pieces);

        {
            std::unique_lock<std::mutex> mlock(m_MutexVar);
            tmp = m_Members;
        }

        for (auto& piece : pieces) {
            TLSClientContext client;
            if (!IsMember((char*)piece) && !IsFailedMember((char*)piece)) {
                if (client.DoClusterClientNoCert((char*)piece) == RSP_SUCCESS) {
                    if (client.PartiallyEstablishClient() == RSP_SUCCESS) {
                        Buffer b((void*)piece, strlen(piece));
                        tmp.push_back(b);
                        bModified = true;
                    }
                }
            }
        }

        if (bModified) {
            Buffer bMbrfile;
            WhereTo(bMbrfile);
            if (bMbrfile.Size() > 0) {
                if (1 == saveToFile((int8_t*)bMbrfile, (int8_t*)bMbrs, (uint32_t)strlen(bMbrs))) {
                    std::unique_lock<std::mutex> mlock(m_MutexVar);
                    m_Members = tmp;
                }
            }
        }
    }
    catch (...) {
        return;
    }

    return;
}

bool ClusterClientManager::IsSandboxedClient()
{
    ResponseHeader* prh;

    try {
        CommandHeader ch = { CMD_GET_CLIENT_SANDBOX_STATE, 0 };
        vector<Buffer> tmp;
        {
            std::unique_lock<std::mutex> mlock(m_MutexVar);
            tmp = m_Members;
        }
        for (auto& mbr : tmp) {
            TLSClientContext client;
            condition_variable cv;
            Buffer bCmd, bResp;
            bCmd.Clear();
            bCmd.Append((void*)&ch, sizeof(CommandHeader));
            if (OsslClientHelper::QueueCommand(client, bCmd, mbr, bResp, cv)) {
                std::unique_lock<std::mutex> mlock(m_MutexVar);
                cv.wait(mlock);

                prh = (ResponseHeader*)bResp;
                if (prh->response == RSP_SUCCESS) {
                    uint8_t* pChar = (uint8_t*)bResp + sizeof(ResponseHeader);
                    if (prh->szData == 1) {
                        return (pChar[0] == 0x01);
                    }
                }
            }
            else {
                return true;
            }
        }
    }
    catch (...) {
        return true;
    }
    
    return true;
}
