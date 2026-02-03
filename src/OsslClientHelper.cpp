/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include "OsslClientHelper.h"
#include "threadPool.h"

using namespace ReiazDean;

extern std::atomic<BOOL> ApplicationStopped;
extern std::atomic<int> NumWorkersRunning;

std::vector<std::tuple<TLSClientContext&, Buffer, Buffer, Buffer&, condition_variable&>> OsslClientHelper::Requests;
std::mutex OsslClientHelper::s_MutexVar;
std::condition_variable OsslClientHelper::s_ConditionVar;
bool OsslClientHelper::s_IsIntitialized = false;
bool OsslClientHelper::s_IsFinalized = false;

void* OsslClientHelper::Initialize(void* args)
{
    Executor();
    return 0;
}

void OsslClientHelper::Finalize()
{
    Requests.clear();
    TLSClientContext::Finalize();
}

bool OsslClientHelper::QueueCommand(TLSClientContext& client, Buffer bCmd, Buffer bHost, Buffer& bResp, condition_variable& cv)
{
    if (!ApplicationStopped) {
        std::unique_lock<std::mutex> mlock(s_MutexVar);
        Requests.push_back(std::tuple<TLSClientContext&, Buffer, Buffer, Buffer&, condition_variable&>(client, bCmd, bHost, bResp, cv));
        s_ConditionVar.notify_all();
        return true;
    }
    return false;
}

void OsslClientHelper::Executor()
{
    std::unique_lock<std::mutex> mlock(s_MutexVar);
    NumWorkersRunning++;
    while (!ApplicationStopped) {
        if (Requests.size() > 0) {
            std::tuple<TLSClientContext&, Buffer, Buffer, Buffer&, condition_variable&> req = Requests.back();
            Requests.pop_back();
            condition_variable& cv = std::get<4>(req);
            try {
                ExecuteCmd(std::get<0>(req), std::get<1>(req), std::get<2>(req), std::get<3>(req));
            }
            catch (...) {
                ResponseHeader failure = { RSP_INTERNAL_ERROR, 0 };
                Buffer& bResp = std::get<3>(req);
                bResp.Clear();
                bResp.Append((void*)&failure, sizeof(ResponseHeader));
            }
            cv.notify_all();
        }
        else
        {
            s_ConditionVar.wait_for(mlock, std::chrono::seconds(1));
        }
    }
    NumWorkersRunning--;
    Finalize();
   
    return;
}

bool OsslClientHelper::ExecuteCmd(TLSClientContext& client, Buffer bCmd, Buffer bHost, Buffer& bResp)
{
    Responses r = RSP_INTERNAL_ERROR;
    ResponseHeader failure = { RSP_INTERNAL_ERROR, 0 };
    bool bRc = false;
    CommandHeader* pch = (CommandHeader*)bCmd;
    ResponseHeader* prh = nullptr;
    Buffer resp;

    if (bCmd.Size() < sizeof(CommandHeader)) {
        return false;
    }

    if (bCmd.Size() != (sizeof(CommandHeader) + pch->szData)) {
        return false;
    }

    bResp.Clear();

    r = client.DoClusterClientNoCert((char*)bHost);
    if (r != RSP_SUCCESS) {
        failure.response = r;
        bResp.Append((void*)&failure, sizeof(ResponseHeader));
        return false;
    }
    
    switch (pch->command)
    {
    case CMD_GET_CLIENT_SANDBOX_STATE:
    case CMD_EXCHANGE_CLUSTER_MBRS:
    case CMD_UPLOAD_CERT_REQUEST:
    case CMD_DOWNLOAD_CERTIFICATE:
    case CMD_GET_CLIENT_SANDBOX_SCRIPT:
        r = client.PartiallyEstablishClient();
        if (r != RSP_SUCCESS) {
            failure.response = r;
            bResp.Append((void*)&failure, sizeof(ResponseHeader));
            return false;
        }
        break;
    case CMD_EXCHANGE_SECRETS:
        r = client.EstablishClusterClient();
        if (r != RSP_SUCCESS) {
            failure.response = r;
            bResp.Append((void*)&failure, sizeof(ResponseHeader));
            return false;
        }
        break;
    default:
        r = client.FullyEstablishClient();
        if (r != RSP_SUCCESS) {
            failure.response = r;
            bResp.Append((void*)&failure, sizeof(ResponseHeader));
            return false;
        }
        break;
    }

    r = client.ExecuteCommand(bCmd, resp);
    if (r != RSP_SUCCESS) {
        failure.response = r;
        bResp.Append((void*)&failure, sizeof(ResponseHeader));
        return false;
    }

    if (resp.Size() < sizeof(ResponseHeader)) {
        failure.response = RSP_INTERNAL_ERROR;
        bResp.Append((void*)&failure, sizeof(ResponseHeader));
        return false;
    }
    prh = (ResponseHeader*)resp;
    if (resp.Size() != (sizeof(ResponseHeader) + prh->szData)) {
        //not an error if we are downloading as the ResponseHeader szData field, is the size of the document to download
        if ((pch->command != CMD_DOWNLOAD_DOCUMENT) && (pch->command != CMD_DOWNLOAD_SW_INSTALLER) && (pch->command != CMD_DOWNLOAD_DECLASSIFIED)) {
            failure.response = RSP_INTERNAL_ERROR;
            bResp.Append((void*)&failure, sizeof(ResponseHeader));
            return false;
        }
    }

    if (prh->response == RSP_SUCCESS) {
        uint8_t* pChar = (uint8_t*)resp + sizeof(ResponseHeader);
        int32_t len = prh->szData;
        switch (pch->command)
        {
        case CMD_GET_CLIENT_SANDBOX_STATE:
        case CMD_EXCHANGE_CLUSTER_MBRS:
        case CMD_UPLOAD_CERT_REQUEST:
        case CMD_DOWNLOAD_CERTIFICATE:
        case CMD_GET_CLIENT_SANDBOX_SCRIPT:
        case CMD_UPLOAD_DOCUMENT:
        case CMD_VERIFY_DOCUMENT:
        case CMD_PUBLISH_DOCUMENT:
        case CMD_DECLASSIFY_DOCUMENT:
        case CMD_GET_DOCUMENT_TREE:
        case CMD_GET_DOCUMENT_NAMES:
            bResp = resp;
            bRc = true;
            break;
        case CMD_DOWNLOAD_SW_INSTALLER:
        case CMD_DOWNLOAD_DOCUMENT:
        case CMD_DOWNLOAD_DECLASSIFIED:
            bResp = resp;//bResp.Append((void*)&len, sizeof(int32_t));
            bRc = true;
            break;
        case CMD_RELOAD_REGISTERED_CLIENTS:
        case CMD_RELOAD_ROOT_KEYS:
        case CMD_STOP_LOCAL_SERVICE:
        case CMD_OOB_GET_SC_CERT:
        case CMD_OOB_SC_SIGN:
        case CMD_OOB_SC_SIGN_DOC_HASH:
        case CMD_NULL:
            break;
        case CMD_GET_MLS_MCS_AES_DEC_KEY:
        case CMD_GET_MLS_MCS_AES_ENC_KEY:
        case CMD_EXCHANGE_SECRETS:
        default:
            if (pChar && (len > 0) && (client.AES_Decrypt(pChar, len, bResp) > 0)) {
                ResponseHeader rh = { RSP_SUCCESS, bResp.Size() };
                bResp.Prepend((void*)&rh, sizeof(ResponseHeader));
                bRc = true;
            }
            else {
                ResponseHeader rh = { RSP_CIPHER_ERROR, 0 };
                bResp.Clear();
                bResp.Append((void*)&rh, sizeof(ResponseHeader));
                bRc = true;
            }
            break;
        }
    }
    else {
        bResp = resp;
        bRc = true;
    }

    return bRc;
}
