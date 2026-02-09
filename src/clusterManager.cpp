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
#include "LocalServer.h"
#include "Utils.h"
#include "clusterManager.h"
#include "NdacConfig.h"
#include "OsslClientHelper.h"

using namespace ReiazDean;

#ifndef AUTH_SERVICE
void SetLocalStatus(WCHAR* pwcText, bool bAppend);
#endif

ClusterManager::ClusterManager()
{
    m_Current = 0;
}

void ClusterManager::FailMember(char* pcMbr)
{
    if (!pcMbr) {
        return;
    }

    try {
        vector<Buffer> tmp;
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        for (auto& mbr : m_Members) {
            if (strcmp(pcMbr, (char*)mbr) == 0) {
                Buffer b(pcMbr, strlen(pcMbr));
                b.NullTerminate();
                m_FailedMembers.push_back(b);
            }
            else {
                tmp.push_back(mbr);
            }
        }
        m_Members = tmp;
#ifndef AUTH_SERVICE
        WCHAR wcBuf[MAX_LINE];
        memset(wcBuf, 0, sizeof(wcBuf));
        swprintf_s(wcBuf, MAX_LINE - 1, L"Cluster member: %S has failed\n", pcMbr);
        SetLocalStatus(wcBuf, true);
#endif
    }
    catch (...) {
        return;
    }
}

void ClusterManager::RecoverMember(char* pcMbr)
{
    if (!pcMbr) {
        return;
    }

    try {
        vector<Buffer> tmp;
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        for (auto& mbr : m_FailedMembers) {
            if (strcmp(pcMbr, (char*)mbr) == 0) {
                Buffer b(pcMbr, strlen(pcMbr));
                b.NullTerminate();
                m_Members.push_back(b);
            }
            else {
                tmp.push_back(mbr);
            }
        }
        m_FailedMembers = tmp;

#ifndef AUTH_SERVICE
        WCHAR wcBuf[MAX_LINE];
        memset(wcBuf, 0, sizeof(wcBuf));
        swprintf_s(wcBuf, MAX_LINE - 1, L"Cluster member: %S has recovered!\n", pcMbr);
        SetLocalStatus(wcBuf, true);
#endif
    }
    catch (...) {
        return;
    }
}

bool ClusterManager::LoadMembers()
{
    Buffer bMbrs;
    Buffer bMbrfile;
    Buffer bData;
    std::vector<char*> pieces;
    std::vector<Buffer> temp;

    try {
        WhereFrom(bMbrfile);
        if (bMbrfile.Size() == 0) {
            return false;
        }

        {
            std::unique_lock<std::mutex> mlock(m_MutexVar);
            if (m_HostName.Size() == 0) {
                char buffer[512];
                DWORD size = sizeof(buffer);
                memset(buffer, 0, size);
                if (GetComputerNameExA(ComputerNameDnsFullyQualified, buffer, &size)) {
                    m_HostName.Append(buffer, size);
                    m_HostName.NullTerminate();
                }
            }
        }

        readFile((char*)bMbrfile, bData);
        if (bData.Size() == 0) {
            return false;
        }

        splitStringA((char*)bData, (char*)"\r\n\t ", pieces);
        for (auto& piece : pieces) {
            Buffer b;
            b.Append(piece, strlen(piece));
            b.NullTerminate();
            temp.push_back(b);
        }
        {
            std::unique_lock<std::mutex> mlock(m_MutexVar);
            m_Members = temp;
        }

        return (m_Members.size() > 0);
    }
    catch (...) {
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        m_Members.clear();
        return false;
    }
}

void ClusterManager::GetMembers(Buffer& bMbrs)
{
    vector<Buffer> tmp;
    {
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        tmp = m_Members;
    }

    try {
        bMbrs.Clear();
        for (auto& mbr : tmp) {
            bMbrs.Append((char*)mbr, strlen((char*)mbr));
            bMbrs.EOLN();
        }
        bMbrs.NullTerminate();
    }
    catch (...) {
        bMbrs.Clear();
    }
}

bool ClusterManager::IsMember(char* pcMbr)
{
    try {
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        if (pcMbr) {
            for (auto& mbr : m_Members) {
                if (strcmp(pcMbr, (char*)mbr) == 0) {
                    return true;
                }
            }
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

bool ClusterManager::IsFailedMember(char* pcMbr)
{
    try {
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        if (pcMbr) {
            for (auto& mbr : m_FailedMembers) {
                if (strcmp(pcMbr, (char*)mbr) == 0) {
                    return true;
                }
            }
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

bool ClusterManager::AddMember(char* pcMbr)
{
    try {
        if (pcMbr && !IsMember(pcMbr)) {
            Buffer b(pcMbr, strlen(pcMbr));
            b.NullTerminate();
            {
                std::unique_lock<std::mutex> mlock(m_MutexVar);
                m_Members.push_back(b);
            }
            return Persist();
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ClusterManager::RemoveMember(char* pcMbr)
{
    try {
        if (!pcMbr) {
            return false;
        }
        else {
            vector<Buffer> tmp;
            std::unique_lock<std::mutex> mlock(m_MutexVar);
            for (auto& mbr : m_Members) {
                if (mbr.Size() > 0) {
                    if (strcmp(pcMbr, (char*)mbr) != 0) {
                        tmp.push_back(mbr);
                    }
                }
            }
            m_Members = tmp;
        }
        return Persist();
    }
    catch (...) {
        return false;
    }
}

bool ClusterManager::RoundRobin(Buffer& bMbr)
{
    try {
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        bMbr.Clear();

        if (m_Members.empty())
            return false;

        bMbr = m_Members[m_Current]; // one copy/move
        m_Current = (m_Current + 1) % m_Members.size();
        return true;
    }
    catch (...) {
        bMbr.Clear();
        return false;
    }
}

bool ClusterManager::ReadMemberFile(Buffer& bMbrs)
{
    Buffer bFile;
    
    try {
        bMbrs.Clear();
        WhereFrom(bFile);
        if (bFile.Size() > 0) {
            struct _stat     buf;
            if (0 == _stat((char*)bFile, &buf)) {
                readFile((char*)bFile, bMbrs);
                if (bMbrs.Size() > 0) {
                    bMbrs.NullTerminate();
                }
            }
        }

        if (bMbrs.Size() == 0) {//non clustered situation
            char buffer[512];
            DWORD size = sizeof(buffer);
            memset(buffer, 0, size);
            if (GetComputerNameExA(ComputerNameDnsFullyQualified, buffer, &size)) {
                bMbrs.Append(buffer, size);
                bMbrs.NullTerminate();
            }
        }

        return (bMbrs.Size() > 0);
    }
    catch (...) {
        bMbrs.Clear();
        return false;
    }
}

