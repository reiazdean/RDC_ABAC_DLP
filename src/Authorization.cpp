/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "Utils.h"
#include "Authorization.h"
#include "MyKeyManager.h"
#include "MyLdap.h"

Authorization::Authorization() {

}

Authorization::~Authorization() {

}

Responses
Authorization::GetEncryptionKeyForUser(
    Mandatory_AC& userMac,
    AuthorizationResponse& ar)
{
    Responses             resp = RSP_INTERNAL_ERROR;
    MyKeyManager&         mkm = MyKeyManager::GetInstance();
    Buffer                bCalculatedKey;
    Buffer                bKeyName;

    try {
        memset(&ar, 0, sizeof(ar));

        if (!mkm.CalculateEncryptionKey(userMac, bCalculatedKey, bKeyName)) {
            return RSP_KEY_GEN_ERROR;
        }

        memcpy(&ar.docMAC, (void*)&userMac, sizeof(Mandatory_AC));
        memcpy(&ar.hsmKeyName, (WCHAR*)bKeyName, wcslen((WCHAR*)bKeyName) * sizeof(WCHAR));

        memcpy(&ar.encryptionKey, (void*)bCalculatedKey, AES_SZ);
        memcpy(&ar.decryptionKey, (void*)bCalculatedKey, AES_SZ);

        return RSP_SUCCESS;
    }
    catch (...) {
        memset(&ar, 0, sizeof(ar));
        return RSP_INTERNAL_ERROR;
    }
}

Responses
Authorization::IsAuthorized(const Mandatory_AC& userMac,
    const Mandatory_AC& docMac)
{
    Responses resp = RSP_NOT_AUTHORIZED;
    int32_t   i = 0;
    char      mcs[MAX_MCS_LEVEL];

    try {
        memset(mcs, 0, MAX_MCS_LEVEL);
        for (i = 0; i < MAX_MCS_LEVEL; i++) {
            mcs[i] = userMac.mcs[i] & docMac.mcs[i];
        }
        if (memcmp(mcs, docMac.mcs, MAX_MCS_LEVEL) != 0) {
            return RSP_MCS_UNAUTHORIZED;
        }

        if (userMac.mls_level < docMac.mls_level) {
            return RSP_MLS_UNAUTHORIZED;
        }

        return RSP_SUCCESS;
    }
    catch (...) {
        return RSP_NOT_AUTHORIZED;
    }
}

Responses
Authorization::GetDecryptionKeyForUser(
    Mandatory_AC& userMac,
    AuthorizationRequest* pAR,
    AuthorizationResponse& ar)
{
    Responses             resp = RSP_INTERNAL_ERROR;
    MyKeyManager&         mkm = MyKeyManager::GetInstance();
    Buffer                bCalculatedKey;
    Mandatory_AC          docMac;

    memset(&ar, 0, sizeof(ar));

    if (!pAR) {
        return RSP_INTERNAL_ERROR;
    }

    try {
        memcpy(&docMac, pAR, sizeof(Mandatory_AC));
        resp = IsAuthorized(userMac, docMac);
        if (resp != RSP_SUCCESS) {
            return resp;
        }

        if (!mkm.CalculateDecryptionKey(pAR->hsmKeyName, docMac, bCalculatedKey)) {
            return RSP_KEY_GEN_ERROR;
        }

        if (GetEncryptionKeyForUser(userMac, ar) == RSP_SUCCESS) {
            memcpy(&ar.decryptionKey, (void*)bCalculatedKey, AES_SZ);
            resp = RSP_SUCCESS;
        }

        return resp;
    }
    catch (...) {
        memset(&ar, 0, sizeof(ar));
        return RSP_INTERNAL_ERROR;
    }
}

Responses
Authorization::CanDownlaod(
    Mandatory_AC& userMac,
    DocHandler& dh,
    uint16_t computerMLS)
{
    AuthorizationRequest ar;
    Mandatory_AC docMac;

    try {
        memset(&ar, 0, sizeof(ar));
        if (!dh.GetAuthRequest(ar)) {
            return RSP_FILE_ERROR;
        }

        memcpy(&docMac, &ar, sizeof(Mandatory_AC));

        if ((computerMLS < docMac.mls_level) || (computerMLS > MAX_MLS_LEVEL)) {
            return RSP_HOST_MLS_UNAUTHORIZED;
        }

        return IsAuthorized(userMac, docMac);
    }
    catch (...) {
        return RSP_INTERNAL_ERROR;
    }
}

Responses
Authorization::CanPublish(
    Buffer& bUPN,
    Mandatory_AC& userMac,
    DocHandler& dh,
    uint16_t computerMLS)
{
    CLdap& ldp = CLdap::GetInstance();

    try {
        if (ldp.IsUserMemberOf(bUPN, (char*)"CN=SecurityOfficers,OU=MandatoryAccess")) {
            return CanDownlaod(userMac, dh, computerMLS);
        }

        return RSP_NOT_AUTHORIZED;
    }
    catch (...) {
        return RSP_INTERNAL_ERROR;
    }
}

