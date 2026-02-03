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
#include "clusterServiceManager.h"
#include "NdacConfig.h"
#include "OsslClientHelper.h"
#include "threadPool.h"

using namespace ReiazDean;

extern std::atomic<bool> Stopped;
#define NUM_CFG_FILES 7
static char MyFiles[NUM_CFG_FILES][32] = {
   "serverKey.key",
   "serverKeyPwd.enc",
   "serverCert.crt",
   "ReiazDeanServer.conf",
   "CAFile.crt",
   "DilithiumSecret.dat",
   "DilithiumPublic.dat" };

bool ClusterServiceManager::PollMembersForSecrets(Buffer& bSecrets)
{
    vector<Buffer> tmp;
   
    {
        std::unique_lock<std::mutex> mlock(m_MutexVar);
        tmp = m_Members;
    }

    try {
        for (auto& mbr : tmp) {
            if (strcmp((char*)mbr, (char*)m_HostName) != 0) {//don't poll self
                CommandHeader ch = { CMD_EXCHANGE_SECRETS, 0 };
                TLSClientContext client;
                condition_variable cv;
                Buffer bCmd, bResp;
                bCmd.Clear();
                bCmd.Append((void*)&ch, sizeof(CommandHeader));
                if (OsslClientHelper::QueueCommand(client, bCmd, mbr, bResp, cv)) {
                    std::unique_lock<std::mutex> mlock(m_MutexVar);
                    cv.wait(mlock);//cv.wait_for(mlock, std::chrono::seconds(10));
                }
                if (bResp.Size() > sizeof(ResponseHeader)) {
                    ResponseHeader* prh = (ResponseHeader*)bResp;
                    char* pc = (char*)bResp + sizeof(ResponseHeader);
                    if (prh->response == RSP_SUCCESS) {
                        if (bResp.Size() == (sizeof(ResponseHeader) + prh->szData)) {
                            bSecrets.Append((void*)pc, prh->szData);
                            return true;
                        }
                    }
                }
#ifdef _DEBUG
                printf("failed to poll %s for password!\n", (char*)mbr);
#endif
            }
        }
    }
    catch (...) {
        bSecrets.Clear();
        return false;
    }

    return false;
}

bool ClusterServiceManager::WhereTo(Buffer& bLocation)
{
    try {
        char folder[] = "\\ClusterConfigs\\";
        NdacServerConfig& cfg = NdacServerConfig::GetInstance();

        bLocation.Clear();
        bLocation = cfg.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
        if (bLocation.Size() == 0) {
            return false;
        }

        bLocation.Append((void*)folder, strlen(folder));
        if (!CreateDirectory((char*)bLocation, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }

        return true;
    }
    catch (...) {
        bLocation.Clear();
        return false;
    }
}

bool ClusterServiceManager::WhereFrom(Buffer& bLocation)
{
    try {
        char folder[] = "\\ClusterConfigs\\";
        NdacServerConfig& cfg = NdacServerConfig::GetInstance();

        bLocation.Clear();
        bLocation = cfg.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
        if (bLocation.Size() == 0) {
            return false;
        }

        bLocation.Append((void*)folder, strlen(folder));
        bLocation.Append(cfg.GetValue(CLUSTER_MEMBERS_FILE));

        return true;
    }
    catch (...) {
        bLocation.Clear();
        return false;
    }
}

bool ClusterServiceManager::Persist()
{
    Buffer bMbrs;
    Buffer bMbrfile;

    try {
        WhereFrom(bMbrfile);
        if (bMbrfile.Size() == 0) {
            return false;
        }

        GetMembers(bMbrs);

        if (bMbrs.Size() > 0) {
            return (1 == saveToFile((int8_t*)bMbrfile, (int8_t*)bMbrs, (uint32_t)strlen((char*)bMbrs)));
        }
        else {
            return (1 == saveToFile((int8_t*)bMbrfile, (int8_t*)"\n", 1));
        }
    }
    catch (...) {
        return false;
    }
}

bool ClusterServiceManager::CopyConfigFilesToClusterConfig()
{
    Buffer bSourceDir;
    Buffer bTargetDir;
    NdacServerConfig& cfg = NdacServerConfig::GetInstance();

    try {
        WhereTo(bTargetDir);
        if (bTargetDir.Size() == 0) {
            return false;
        }
        bSourceDir.Append(cfg.GetMyFilePath());
        bSourceDir.Append((void*)"\\", strlen("\\"));
        if (bSourceDir.Size() == 0) {
            return false;
        }
        for (int i = 0; i < NUM_CFG_FILES; i++) {
            Buffer bSourceFile(bSourceDir);
            Buffer bTargetFile(bTargetDir);

            bSourceFile.Append((void*)MyFiles[i], strlen(MyFiles[i]));
            bTargetFile.Append((void*)MyFiles[i], strlen(MyFiles[i]));
            bSourceFile.NullTerminate();
            bTargetFile.NullTerminate();
            if (!CopyFile((char*)bSourceFile, (char*)bTargetFile, FALSE)) {
                printf("\nFAILED to copy from %s to %s\n", (char*)bSourceFile, (char*)bTargetFile);
                return false;
            }
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool ClusterServiceManager::CopyConfigFilesFromClusterConfig(char* path)
{
    Buffer bSourceDir;
    Buffer bTargetDir;
    NdacServerConfig& cfg = NdacServerConfig::GetInstance();

    if (!path) {
        return false;
    }

    try {
        bSourceDir.Append((void*)path, strlen(path));
        bSourceDir.Append((void*)"\\classified\\ClusterConfigs\\", strlen("\\classified\\ClusterConfigs\\"));

        bTargetDir.Append(cfg.GetMyFilePath());
        {
            Buffer bLocation = bTargetDir;
            bLocation.NullTerminate();
            if (!CreateDirectory((char*)bLocation, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }
        }
        bTargetDir.Append((void*)"\\", strlen("\\"));
        if (bTargetDir.Size() == 0) {
            return false;
        }
        for (int i = 0; i < NUM_CFG_FILES; i++) {
            Buffer bSourceFile(bSourceDir);
            Buffer bTargetFile(bTargetDir);

            bSourceFile.Append((void*)MyFiles[i], strlen(MyFiles[i]));
            bTargetFile.Append((void*)MyFiles[i], strlen(MyFiles[i]));
            bSourceFile.NullTerminate();
            bTargetFile.NullTerminate();
            if (!CopyFile((char*)bSourceFile, (char*)bTargetFile, TRUE)) {
                printf("\nFailed to copy from %s to %s\n", (char*)bSourceFile, (char*)bTargetFile);
                return false;
            }
            //printf("\ncopy from %s to %s\n", (char*)bSourceFile, (char*)bTargetFile);
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool ClusterServiceManager::JoinCluster(char* path)
{
    char buffer[512];
    DWORD size = sizeof(buffer);
    Buffer bMbrFile;
    Buffer bData;

    if (!path) {
        return false;
    }

    try {
        bMbrFile.Append((void*)path, strlen(path));
        bMbrFile.Append((void*)"\\classified\\ClusterConfigs\\ClusterMembers.conf", strlen("\\classified\\ClusterConfigs\\ClusterMembers.conf"));
        bMbrFile.NullTerminate();
        readFile((char*)bMbrFile, bData);
        if (bData.Size() == 0) {
            printf("\nFailed! Cluster was never created!\n");
            return false;
        }

        memset(buffer, 0, size);
        if (!GetComputerNameExA(ComputerNameDnsFullyQualified, buffer, &size)) {
            printf("\nFailed! Cannot determine this computers host name!\n");
            return false;
        }

        if (strstr((char*)bData, buffer)) {
            printf("\nFailed! %s is already a cluster member!\n", buffer);
            return false;
        }

        if (CopyConfigFilesFromClusterConfig(path)) {
            bData.EOLN();
            bData.Append((void*)buffer, strlen(buffer));
            bData.NullTerminate();
            if (1 == saveToFile((int8_t*)bMbrFile, (int8_t*)bData, (uint32_t)strlen((char*)bData))) {
                printf("\nSuccess joining %s to the cluster. Members are:\n%s\n", buffer, (char*)bData);
                return true;
            }
        }

        printf("\nFAILED joining %s to the cluster\n", buffer);

        return false;
    }
    catch (...) {
        return false;
    }
}

bool ClusterServiceManager::UnjoinCluster()
{
    char buffer[512];
    DWORD size = sizeof(buffer);

    try {
        memset(buffer, 0, size);
        if (!GetComputerNameExA(ComputerNameDnsFullyQualified, buffer, &size)) {
            printf("\nFailed! Cannot determine this computers host name!\n");
            return false;
        }

        if (!IsMember(buffer)) {
            printf("\nFailed! %s is not a cluster member!\n", buffer);
            return false;
        }
        else {
            return RemoveMember(buffer);
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

bool ClusterServiceManager::CreateCluster()
{
    struct _stat buf;
    char buffer[512];
    DWORD size = sizeof(buffer);
    NdacServerConfig& cfg = NdacServerConfig::GetInstance();
    Buffer bTestFile = cfg.GetValue(DOCUMENT_ROOT_FILE_LOCATION);

    try {
        if (!cfg.IsValid()) {
            printf("\nFailed! The service has not yet been configured!\n");
            return false;
        }

        if (strncmp((char*)"\\\\", (char*)bTestFile, 2) != 0) {
            printf("\nFailed! The document storage location is not a shared folder in UNC named format!\n");
            return false;
        }

        bTestFile.Append((void*)"\\ClusterConfigs\\ClusterMembers.conf", strlen("\\ClusterConfigs\\ClusterMembers.conf"));
        if (_stat((char*)bTestFile, &buf) == 0) {
            printf("\nFailed! Cluster is already created!\n");
            return false;
        }

        memset(buffer, 0, size);
        if (GetComputerNameExA(ComputerNameDnsFullyQualified, buffer, &size)) {
            if (CopyConfigFilesToClusterConfig()) {
                Buffer bMbrfile;
                WhereFrom(bMbrfile);
                if (1 == saveToFile((int8_t*)bMbrfile, (int8_t*)buffer, (uint32_t)strlen(buffer))) {//if (AddMember(buffer)) {
                    printf("\nSuccess creating the cluster with %s!\n", buffer);
                    return true;
                }
            }
        }

        printf("\nFAILED creating the cluster!\n");

        return false;
    }
    catch (...) {
        return false;
    }
}

void ClusterServiceManager::SetSecrets(Buffer bSecrets)
{
    std::unique_lock<std::mutex> mlock(m_MutexVar);
    m_Secrets = bSecrets;
}

Buffer ClusterServiceManager::GetSecrets()
{
    std::unique_lock<std::mutex> mlock(m_MutexVar);
    return m_Secrets;
}
