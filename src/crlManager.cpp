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
#include "crlManager.h"
#include "NdacConfig.h"
#include "threadPool.h"
#include "MyLdap.h"

using namespace ReiazDean;
mutex CRLManager::s_MutexVar;
condition_variable CRLManager::s_ConditionVar;
time_t CRLManager::s_LastCRLtime;
vector<Buffer>  CRLManager::s_RevokedClientCertSNs[NUM_REVOKED_BUCKETS];

void CRLManager::Initialize()
{
    time(&s_LastCRLtime);
    LoadRevokedSNs();
}

void CRLManager::PersistRevokedSNs()
{
    FILE* fp = nullptr;
    Buffer bName;
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();
    try {
        bName = scfg.GetValue(REVOKED_CERT_SN_FILE);
        fp = f_open_f((char*)bName, (char*)"wb");
        if (!fp) {
            return;
        }
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        for (int i = 0; i < NUM_REVOKED_BUCKETS; i++) {
            vector<Buffer>& bucket = s_RevokedClientCertSNs[i];
            for (const Buffer& b : bucket) {
                Buffer sn = b;
                Buffer hex;
                hexEncode((uint8_t*)sn, sn.Size(), hex);
                hex.EOLN();
                fwrite(hex, 1, hex.Size(), fp);
            }
        }
        fclose(fp);
        fp = nullptr;
    }
    catch (...) {
        if (fp) {
            fclose(fp);
        }
    }
}

void CRLManager::LoadRevokedSNs()
{
    char line[64];
    FILE* fp = nullptr;
    Buffer bName;
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();
    try {
        bName = scfg.GetValue(REVOKED_CERT_SN_FILE);
        fp = f_open_f((char*)bName, (char*)"rt");
        if (!fp) {
            return;
        }

        memset(line, 0, sizeof(line));
        while (fgets(line, sizeof(line) - 1, fp)) {
            if (strlen(line) > 0) {
                Buffer raw;
                line[strlen(line) - 1] = 0;//remove eoln
                if (hexDecode((uint8_t*)line, (uint32_t)strlen(line), raw)) {
                    RememberRevokedSN(raw);
                }
            }
            memset(line, 0, sizeof(line));
        }
        fclose(fp);
        fp = nullptr;
    }
    catch (...) {
        if (fp) {
            fclose(fp);
        }
    }
}

int CRLManager::WhichBucket(const Buffer& bSN)
{
    try {
        Buffer bTmp = bSN;
        uint8_t sum = 0;
        for (uint32_t i = 0; i < bTmp.Size(); i++) {
            sum += (uint8_t)bTmp[i];
        }
        return sum % NUM_REVOKED_BUCKETS;
    }
    catch (...) {
        throw("Invalid bucket!");
    }
}

void CRLManager::RememberRevokedSN(const Buffer& bSN)
{
    try {
        int i = WhichBucket(bSN);
        Buffer bTmp = bSN;
        vector<Buffer>& bucket = s_RevokedClientCertSNs[i];
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        for (const Buffer& b : bucket) {
            Buffer sn = b;
            if (sn.Size() == bTmp.Size()) {
                if (memcmp((void*)sn, (void*)bTmp, sn.Size()) == 0) {
                    return;//dont't add to the list because it is already there
                }
            }
        }
        bucket.push_back(bTmp);
    }
    catch (...) {
        return;
    }
}

bool CRLManager::IsRevokedSNCached(const Buffer& bSN)
{
    try {
        int i = WhichBucket(bSN);
        Buffer bTmp = bSN;
        vector<Buffer>& bucket = s_RevokedClientCertSNs[i];
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        for (const Buffer& b : bucket) {
            Buffer sn = b;
            if (sn.Size() == bTmp.Size()) {
                if (memcmp((void*)sn, (void*)bTmp, sn.Size()) == 0) {
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

bool CRLManager::IsCertificateRevoked(const Buffer& bCert)
{
    try {
        Buffer bCRL;
        Buffer bCDP;
        Buffer bSN;
        Certificate cert(bCert);

        if (!cert.GetSerialNumber(bSN)) {
            return true;
        }

        if (IsRevokedSNCached(bSN)) {
            return true;
        }

        {
            time_t now;
            std::unique_lock<std::mutex> mlock(s_MutexVar);
            time(&now);
            if ((s_LatestCRL.Size() == 0) || (difftime(now, s_LastCRLtime) >= 300.0f)) {//make this configurable
                if (cert.GetLdapCDP(bCDP)) {
                    if (CLdap::ProcessURI((char*)bCDP, bCRL)) {
                        s_LatestCRL = bCRL;
                        s_LastCRLtime = now;
                    }
                }
            }
            else {
                bCRL = s_LatestCRL;
            }
        }

        if (bCRL.Size() == 0) {
            return true;
        }
        else {
            CertificateRL crl(bCRL);
            if (crl.IsNotVerified()) {//we can't trust the crl returned by the cert cdp, so don't trust the cert
                return true;
            }
            if (crl.IsRevoked(bSN)) {
                crl.RememberRevokedSNs();
                return true;
            }
        }

        return false;
    }
    catch (...) {
        return true;
    }
}
