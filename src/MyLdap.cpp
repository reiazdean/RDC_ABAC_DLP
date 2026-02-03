/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include <stdlib.h>
#ifndef AUTH_SERVICE
#include <sspi.h>
#endif
#include "NdacConfig.h"
#include "MyLdap.h"
//dnf install openldap-devel

using namespace ReiazDean;

extern Buffer* pPasswordBuffer;

#define			NUM_RETURNS			1000
#define			SIZE_LIMIT			1000
#define			MAX_USERS			10000

mutex CLdap::mutexVar;

bool CLdap::ParseURI(const char* cdp, Buffer& host, Buffer& base, Buffer& filter, Buffer& attr, ULONG& scope)
{
    int8_t seps[] = "/?";
    int8_t* token = NULL;
    int8_t* last = NULL;
    std::vector<Buffer> pieces;
    Buffer bScope;
    
    try {
        Buffer bTmp((char*)cdp, strlen(cdp));
        bTmp.NullTerminate();
        token = strToken((int8_t*)bTmp, seps, &last);
        while (token) {
            Buffer b;
            size_t sz = strlen((char*)token);
            int i = 0;
            do {
                if (token[i] == '%') {
                    Buffer c;
                    uint8_t h[3];
                    h[0] = (uint8_t)token[i + 1];
                    h[1] = (uint8_t)token[i + 2];
                    h[2] = 0;
                    hexDecode(h, 2, c);
                    b.Append((void*)c, 1);
                    i += 3;
                }
                else {
                    b.Append(&token[i], 1);
                    i++;
                }

            } while (i < sz);
            b.NullTerminate();
            pieces.push_back(b);
            token = strToken(NULL, seps, &last);
        }

        if (pieces.size() == 6) {//host included
            host = pieces[1];
            base = pieces[2];
            attr = pieces[3];
            bScope = pieces[4];
            filter = pieces[5];
        }
        else if (pieces.size() == 5) {//no host
            base = pieces[1];
            attr = pieces[2];
            bScope = pieces[3];
            filter = pieces[4];
        }
        else {
            return false;
        }

        if (strcmp((char*)bScope, (char*)"base") == 0) {
            scope = LDAP_SCOPE_BASE;
        }
        else if (strcmp((char*)bScope, (char*)"sub") == 0) {
            scope = LDAP_SCOPE_SUBTREE;
        }
        else if (strcmp((char*)bScope, (char*)"one") == 0) {
            scope = LDAP_SCOPE_ONELEVEL;
        }
        else {
            return false;
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::ProcessURI(char* cdp, Buffer& bOut)
{
    bool bRc = false;
    Buffer host;
    Buffer base;
    Buffer filter;
    Buffer attr;
    ULONG scope = 99999;

    if (!cdp) {
        return false;
    }

    if (!ParseURI(cdp, host, base, filter, attr, scope)) {
        return false;
    }

    if (TheCLdap.IsAuthenticated()) {
        return TheCLdap.DownloadCertURI(cdp, bOut);
    }
    else {
        CLdap ldp;
        if (!ldp.Connect(host)) {
            return false;
        }

        //if no host, then querying AD with TLS from a domain member
        if (host.Size() == 0) {
            if (ldap_start_tls_s(ldp.m_pLdapConnection, NULL, NULL, NULL, NULL) != LDAP_SUCCESS) {
                return false;
            }
            ldp.m_bIsSSLEnabled = true;
        }

        if (ldap_bind_s(ldp.m_pLdapConnection, NULL, NULL, (host.Size() == 0) ? LDAP_AUTH_NEGOTIATE : LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
            return false;
        }
        ldp.m_bAuthenticated = true;

        bRc = ldp.DownloadCertURI(cdp, bOut);

        ldp.Disconnect();
    }
    return bRc;
}

CLdap::CLdap()
{
    m_pLdapConnection = NULL;
    m_bConnected = false;
    m_bAuthenticated = false;
    m_bIsSSLEnabled = false;
    m_Host.Append((void*)"AD\0", 3);
    m_QDN.Append((void*)"a.b.c\0", 6);
}

CLdap::~CLdap()
{
}

bool CLdap::Connect(Buffer& bHostURL)
{
    std::unique_lock<std::mutex> mlock(mutexVar);
    //-------------------------------------------------------
    // Set session options.
    //-------------------------------------------------------
    uint32_t version = LDAP_VERSION3;
    uint32_t numReturns = NUM_RETURNS;
    uint32_t lRtn = LDAP_CONNECT_ERROR;
    bool isAD = true;

    try {
        m_Host = bHostURL;
        if ((m_Host.Size() > 0) &&
            (strcmp((char*)m_Host, (char*)"AD") != 0)) {
            isAD = false;
        }

        m_pLdapConnection = ldap_initA(isAD ? NULL : (char*)m_Host, LDAP_PORT);
        if (!m_pLdapConnection) {
#ifdef _DEBUG
            printf("ldap_initA = 0x%x\n", lRtn);
#endif
            return false;
        }

        // Set the version to 3.0 (default is 2.0).
        lRtn = ldap_set_option(
            m_pLdapConnection,           // Session handle
            LDAP_OPT_PROTOCOL_VERSION, // Option
            (void*)&version);         // Option value
        if (lRtn != LDAP_SUCCESS)
            return false;

        // Set the limit on the number of entries returned to unlimited.
        lRtn = ldap_set_option(
            m_pLdapConnection,       // Session handle
            LDAP_OPT_SIZELIMIT,    // Option
            (void*)&numReturns);  // Option value
        if (lRtn != LDAP_SUCCESS)
            return false;

        // Set the limit on the number of entries returned to 10.
        lRtn = ldap_set_option(
            m_pLdapConnection,       // Session handle
            LDAP_OPT_REFERRALS,    // Option
            LDAP_OPT_OFF);  // Option value
        if (lRtn != LDAP_SUCCESS)
            return false;

#ifdef OS_WIN32
        lRtn = ldap_connect(m_pLdapConnection, NULL);
#else
        //lRtn = ldap_connect(m_pLdapConnection);
#endif

        if (lRtn != LDAP_SUCCESS) {
            return false;
        }

        m_bConnected = true;

        return true;
    }
    catch (...) {
        return false;
    }
}

//connecting to AD from a domain member
bool CLdap::Connect()
{
    std::unique_lock<std::mutex> mlock(mutexVar);
    //-------------------------------------------------------
    // Set session options.
    //-------------------------------------------------------
    uint32_t version = LDAP_VERSION3;
    uint32_t numReturns = NUM_RETURNS;
    uint32_t lRtn = LDAP_CONNECT_ERROR;

    try {
        m_Host.Append((void*)"AD", 2);
        m_Host.NullTerminate();
        
        m_pLdapConnection = ldap_initA(NULL, LDAP_PORT);
        if (!m_pLdapConnection) {
#ifdef _DEBUG
            printf("ldap_initA = 0x%x\n", lRtn);
#endif
            return false;
        }

        // Set the version to 3.0 (default is 2.0).
        lRtn = ldap_set_option(
            m_pLdapConnection,           // Session handle
            LDAP_OPT_PROTOCOL_VERSION, // Option
            (void*)&version);         // Option value
        if (lRtn != LDAP_SUCCESS)
            return false;

        // Set the limit on the number of entries returned to unlimited.
        lRtn = ldap_set_option(
            m_pLdapConnection,       // Session handle
            LDAP_OPT_SIZELIMIT,    // Option
            (void*)&numReturns);  // Option value
        if (lRtn != LDAP_SUCCESS)
            return false;

        // Set the limit on the number of entries returned to 10.
        lRtn = ldap_set_option(
            m_pLdapConnection,       // Session handle
            LDAP_OPT_REFERRALS,    // Option
            LDAP_OPT_OFF);  // Option value
        if (lRtn != LDAP_SUCCESS)
            return false;

#ifdef OS_WIN32
        lRtn = ldap_connect(m_pLdapConnection, NULL);
#else
        //lRtn = ldap_connect(m_pLdapConnection);
#endif

        if (lRtn != LDAP_SUCCESS) {
            return false;
        }

        m_bConnected = true;

        return true;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::Bind(Buffer& bUserDN, Buffer& bPwd, Buffer& bFQDN)
{
    uint32_t          lRtn = LDAP_INAPPROPRIATE_AUTH;
    std::unique_lock<std::mutex> mlock(mutexVar);

    try {
        m_QDN = bFQDN;

#ifdef OS_WIN32
        lRtn = ldap_start_tls_s(m_pLdapConnection, NULL, NULL, NULL, NULL);//WIN-7AO8LH8BHSJ.reiazdean.ca
        if (lRtn != LDAP_SUCCESS) {
            return false;
        }
#else
        lRtn = LDAP_SUCCESS;// ldap_start_tls_s(m_pLdapConnection, NULL, NULL);
        if (lRtn != LDAP_SUCCESS) {
            char* msg = NULL;
            ldap_get_option(m_pLdapConnection, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&msg);
            printf("ldap_start_tls_s failed: 0x%x  %s\n", lRtn, msg);
            ldap_memfree(msg);
            return false;
        }
#endif

        m_bIsSSLEnabled = true;

        lRtn = ldap_simple_bind_sA(m_pLdapConnection, (char*)bUserDN, (char*)bPwd);
        if (lRtn != LDAP_SUCCESS)
        {
            return false;
        }
#ifdef _DEBUG
        printf("bound\n");
#endif
        m_bAuthenticated = true;
        return true;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::Bind(Buffer& bFQDN)
{
    uint32_t lRtn = LDAP_INAPPROPRIATE_AUTH;
    ULONG ulAuthType = LDAP_AUTH_NEGOTIATE;

    std::unique_lock<std::mutex> mlock(mutexVar);

    try {
        m_QDN = bFQDN;

        lRtn = ldap_start_tls_s(m_pLdapConnection, NULL, NULL, NULL, NULL);//WIN-7AO8LH8BHSJ.reiazdean.ca
        if (lRtn != LDAP_SUCCESS) {
            return false;
        }

        m_bIsSSLEnabled = true;
#ifndef AUTH_SERVICE
        SEC_WINNT_AUTH_IDENTITY secIdent;
        secIdent.User = (unsigned short*)NULL;
        secIdent.UserLength = 0;
        secIdent.Password = (unsigned short*)NULL;
        secIdent.PasswordLength = 0;
        secIdent.Domain = (unsigned short*)(WCHAR*)m_Host;
        secIdent.DomainLength = (uint32_t)wcslen((WCHAR*)m_Host);
        secIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#endif
        lRtn = ldap_bind_s(
            m_pLdapConnection,      // Session Handle
            NULL,//m_pQDN,                // Domain DN
            NULL,//(PWCHAR)&secIdent,     // Credential structure
            ulAuthType); // Auth mode

        m_bAuthenticated = (lRtn == LDAP_SUCCESS);
        return m_bAuthenticated;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::Bind()
{
    uint32_t lRtn = LDAP_INAPPROPRIATE_AUTH;
    
    std::unique_lock<std::mutex> mlock(mutexVar);

    try {
        lRtn = ldap_start_tls_s(m_pLdapConnection, NULL, NULL, NULL, NULL);
        if (lRtn != LDAP_SUCCESS) {
            return false;
        }

        m_bIsSSLEnabled = true;

        lRtn = ldap_bind_s(m_pLdapConnection, NULL, NULL, LDAP_AUTH_NEGOTIATE); // Auth mode
        if (lRtn == LDAP_SUCCESS) {
            // Query RootDSE
            LDAPMessage* searchResult = NULL;
            char* pMyAttributes[5];
            pMyAttributes[0] = (char*)"defaultNamingContext";
            pMyAttributes[1] = (char*)"dnsHostName";
            pMyAttributes[2] = NULL;
            lRtn = ldap_search_sA(m_pLdapConnection, (char*)"", LDAP_SCOPE_BASE, (char*)"(objectClass=*)",
                pMyAttributes,
                0, &searchResult);

            if (lRtn == LDAP_SUCCESS) {
                LDAPMessage* pEntry = NULL;
                BerElement* pBer = NULL;
                char* pAttribute = NULL;

                pEntry = ldap_first_entry(m_pLdapConnection, searchResult);
                if (pEntry) {
                    pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
                    while (pAttribute) {
                        if (strcmp(pAttribute, "dnsHostName") == 0) {
                            berval** ppBerValue = NULL;
                            ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                            if (ppBerValue) {
                                m_Host.Clear();
                                m_Host.Append(ppBerValue[0]->bv_val, ppBerValue[0]->bv_len);
                                m_Host.NullTerminate();
                                ldap_value_free_len(ppBerValue);
                            }
                        }
                        else if (strcmp(pAttribute, "defaultNamingContext") == 0) {
                            berval** ppBerValue = NULL;
                            ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                            if (ppBerValue) {
                                m_QDN.Clear();
                                m_QDN.Append(ppBerValue[0]->bv_val, ppBerValue[0]->bv_len);
                                m_QDN.NullTerminate();
                                ldap_value_free_len(ppBerValue);
                            }
                        }
                        ldap_memfreeA(pAttribute);
                        pAttribute = NULL;
                        pAttribute = ldap_next_attributeA(m_pLdapConnection, pEntry, pBer);
                    }
                    if (pAttribute) {
                        ldap_memfreeA(pAttribute);
                    }
                    if (pBer) {
                        ber_free(pBer, 0);
                    }
                }
#ifdef _DEBUG
                printf("host = %s  dn = %s\n", (char*)m_Host, (char*)m_QDN);
#endif
            }
            
            if (searchResult) {
                ldap_msgfree(searchResult);
            }
        }

        m_bAuthenticated = (lRtn == LDAP_SUCCESS);
        return m_bAuthenticated;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::Disconnect()
{
    std::unique_lock<std::mutex> mlock(mutexVar);
#ifdef OS_WIN32
    if (m_pLdapConnection != NULL)
    {
        if (m_bIsSSLEnabled)
            ldap_stop_tls_s(m_pLdapConnection);
        ldap_unbind(m_pLdapConnection);
    }
#endif
    m_pLdapConnection = NULL;
    m_bConnected = false;
    m_bAuthenticated = false;
    m_bIsSSLEnabled = false;

    return true;
}

bool  CLdap::IsComputerInDomain(const char* bComp, bool& bSandboxed, uint16_t& mls)
{
    bool                    bRC = false;
    uint32_t                errorCode = LDAP_SUCCESS;
    char                    cFilter[256];
    char                    cSearchBase[256];
    char* pMyAttributes[5];
    LDAPMessage* pMsg = NULL;
    uint32_t                lRtn = LDAP_CONNECT_ERROR;

    std::unique_lock<std::mutex> mlock(mutexVar);

    if (!m_pLdapConnection || !bComp)
        return false;

    try {
        memset(cSearchBase, 0, sizeof(cSearchBase));
        stringWrite((int8_t*)cSearchBase, sizeof(cSearchBase) - 1, (int8_t*)"CN=Computers,%s", (char*)m_QDN);

        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1, (int8_t*)"(&(objectClass=computer)(dNSHostName=%s))", (char*)bComp);

        pMyAttributes[0] = (char*)"*";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            cSearchBase,
            LDAP_SCOPE_ONELEVEL,
            cFilter,
            pMyAttributes,
            0,
            &pMsg
        );
        if (lRtn != LDAP_SUCCESS)
            return false;

        lRtn = ldap_count_entries(m_pLdapConnection, pMsg);
        if (lRtn == 1) {
            LDAPMessage* pEntry = NULL;
            BerElement* pBer = NULL;
            char* pAttribute = NULL;

            pEntry = ldap_first_entry(m_pLdapConnection, pMsg);
            pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
            mls = MAX_MLS_LEVEL * 2;
            while (pAttribute) {
                if (strcmp(pAttribute, "memberOf") == 0) {
                    berval** ppBerValue = NULL;
                    uint32_t       iValue = 0;

                    ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                    if (ppBerValue != NULL) {
                        uint32_t z;
                        iValue = ldap_count_values_len(ppBerValue);//remember, the memberOf attribute can return multiple values for each group the user belongs to
                        for (z = 0; z < iValue; z++) {
                            int i = MAX_MLS_LEVEL + 1;
                            if (strstr(ppBerValue[z]->bv_val, "CN=NonSandBoxedComputers,OU=MandatoryAccess")) {
                                bSandboxed = false;
                            }
                            do {
                                char cn[256];
                                stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=l%d,OU=MLS,OU=MandatoryAccess", i);
                                if (strstr(ppBerValue[z]->bv_val, cn)) {
                                    mls = i;
                                    break;
                                }
                                i--;
                            } while (i >= 0);
                        }
                        ldap_value_free_len(ppBerValue);
                    }
                }
                //printf("attr = %s\n", pAttribute);
                ldap_memfreeA(pAttribute);
                pAttribute = NULL;
                pAttribute = ldap_next_attributeA(m_pLdapConnection, pEntry, pBer);
            }
            if (pAttribute) {
                ldap_memfreeA(pAttribute);
            }
            if (pBer) {
                ber_free(pBer, 0);
            }
        }
        
        if (pMsg) {
            ldap_msgfree(pMsg);
        }

        return (lRtn == 1);
    }
    catch (...) {
        mls = 0;
        bSandboxed = true;
        return false;
    }
    
    return false;
}

bool  CLdap::GetGroupDescription(const char* pcDN, Buffer& bGroup)
{
    bool            bRC = false;
    uint32_t        errorCode = LDAP_SUCCESS;
    char            cFilter[1024];
    char* pMyAttributes[5];
    LDAPMessage* pMsg = NULL;
    uint32_t        lRtn = LDAP_CONNECT_ERROR;

    if (!m_pLdapConnection)
        return false;

    try {
        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1,
            (int8_t*)"(&(objectCategory=group)(distinguishedName=%s))", (int8_t*)pcDN);

        pMyAttributes[0] = (char*)"description";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            (char*)m_QDN,
            LDAP_SCOPE_SUBTREE,//LDAP_SCOPE_ONELEVEL
            cFilter,
            pMyAttributes,
            0,
            &pMsg
        );

        if (lRtn != LDAP_SUCCESS)
            return false;

        lRtn = ldap_count_entries(m_pLdapConnection, pMsg);
        if (lRtn == 1) {
            LDAPMessage* pEntry = NULL;
            BerElement* pBer = NULL;
            char* pAttribute = NULL;

            pEntry = ldap_first_entry(m_pLdapConnection, pMsg);
            pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
            if (pAttribute) {
                berval** ppBerValue = NULL;
                uint32_t   iValue = 0;

                ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                if (ppBerValue) {
                    bGroup.Clear();
                    bGroup.Append(ppBerValue[0]->bv_val, ppBerValue[0]->bv_len);
                    bGroup.NullTerminate();// Append((void*)"\0", 1);
                    ldap_value_free_len(ppBerValue);
                    bRC = true;
                }
                ldap_memfreeA(pAttribute);
                pAttribute = NULL;
            }
            if (pAttribute) {
                ldap_memfreeA(pAttribute);
            }
            if (pBer) {
                ber_free(pBer, 0);
            }
        }

        if (pMsg) {
            ldap_msgfree(pMsg);
        }

        return bRC;
    }
    catch (...) {
        bGroup.Clear();
        return false;
    }
}

bool CLdap::FindUser(Buffer& bUPN, Mandatory_AC& mac)
{
    bool                    bRC = false;
    uint32_t                errorCode = LDAP_SUCCESS;
    char                    cFilter[1024];
    char* pMyAttributes[5];
    LDAPMessage* pMsg = NULL;
    uint32_t                lRtn = LDAP_CONNECT_ERROR;

    if (!m_pLdapConnection)
        return false;

    try {
        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1, (int8_t*)"userPrincipalName=%s", (char*)bUPN);

        pMyAttributes[0] = (char*)"*";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            (char*)m_QDN,
            LDAP_SCOPE_SUBTREE,//LDAP_SCOPE_ONELEVEL
            cFilter,
            pMyAttributes,
            0,
            &pMsg
        );
        if (lRtn != LDAP_SUCCESS)
            return false;

        lRtn = ldap_count_entries(m_pLdapConnection, pMsg);
        if (lRtn != 1)
            return false;

        /*
        for (e = ldap_first_entry(m_pLdapConnection, pMsg); e != NULL; e = ldap_next_entry(m_pLdapConnection, e)) {
            if ((dn = ldap_get_dn(m_pLdapConnection, e)) != NULL) {
                printf("dn: %s   count = %u\n", dn, lRtn);
                ldap_memfree(dn);
            }
        }*/

        if (pMsg) {
            ldap_msgfree(pMsg);
        }
        pMsg = NULL;

        return FindGroups(bUPN, mac);
    }
    catch (...) {
        if (pMsg)
            ldap_msgfree(pMsg);

        return false;
    }
}

bool CLdap::FindGroups(Buffer& bUPN, Mandatory_AC& mac)
{
    bool                    bRC = false;
    uint32_t                errorCode = LDAP_SUCCESS;
    char                    cFilter[1024];
    LDAPMessage* pSearchResult = NULL;
    char* dn = NULL;
    char* pMyAttributes[2];
    uint32_t               lRtn = LDAP_CONNECT_ERROR;


    if (!m_pLdapConnection)
        return false;

    try {
        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1, (int8_t*)"userPrincipalName=%s", (char*)bUPN);

        pMyAttributes[0] = (char*)"*";// "memberOf";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            (char*)m_QDN,
            LDAP_SCOPE_SUBTREE,//LDAP_SCOPE_ONELEVEL,//LDAP_SCOPE_SUBTREE,
            cFilter,
            pMyAttributes,
            0,
            &pSearchResult
        );
        if (lRtn != LDAP_SUCCESS)
            return false;

        lRtn = ldap_count_entries(m_pLdapConnection, pSearchResult);
        if (lRtn == 1) {
            LDAPMessage* pEntry = NULL;
            BerElement* pBer = NULL;
            char* pAttribute = NULL;

            pEntry = ldap_first_entry(m_pLdapConnection, pSearchResult);
            pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
            while (pAttribute) {
                if (strcmp(pAttribute, "memberOf") == 0) {
                    berval** ppBerValue = NULL;
                    uint32_t       iValue = 0;

                    ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                    if (ppBerValue != NULL) {
                        uint32_t z;
                        iValue = ldap_count_values_len(ppBerValue);//remember, the memberOf attribute can return multiple values for each group the user belongs to
                        for (z = 0; z < iValue; z++) {
                            int32_t i = 0;
                            char cn[256];

                            for (i = 0; i < MAX_MLS_LEVEL; i++) {
                                stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=l%d,OU=MLS,OU=MandatoryAccess", i);
                                if (strstr(ppBerValue[z]->bv_val, cn)) {
                                    Buffer bG;
                                    stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=l%d,OU=MLS,OU=MandatoryAccess,%s", i, (int8_t*)m_QDN);
                                    if (GetGroupDescription(cn, bG)) {
                                        mac.mls_level = i;
                                        memset(&mac.mls_desc, 0, MAX_DESCRIPTION_SZ);
                                        memcpy(&mac.mls_desc, (void*)bG, minimum(bG.Size(), MAX_DESCRIPTION_SZ - 1));
                                        memset(&mac.implied_mls_desc[i], 0, MAX_DESCRIPTION_SZ);
                                        memcpy(&mac.implied_mls_desc[i], (void*)bG, minimum(bG.Size(), MAX_DESCRIPTION_SZ - 1));
                                        for (int32_t j = 0; j < i; j++) {
                                            Buffer bGj;
                                            stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=l%d,OU=MLS,OU=MandatoryAccess,%s", j, (int8_t*)m_QDN);
                                            if (GetGroupDescription(cn, bGj)) {
                                                memset(&mac.implied_mls_desc[j], 0, MAX_DESCRIPTION_SZ);
                                                memcpy(&mac.implied_mls_desc[j], (void*)bGj, minimum(bGj.Size(), MAX_DESCRIPTION_SZ - 1));
                                            }
                                        }
                                    }
                                }
                            }
                            for (i = 0; i < MAX_MCS_LEVEL; i++) {
                                stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=c%d,OU=MCS,OU=MandatoryAccess", i);
                                if (strstr(ppBerValue[z]->bv_val, cn)) {
                                    Buffer bG;
                                    stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=c%d,OU=MCS,OU=MandatoryAccess,%s", i, (int8_t*)m_QDN);
                                    if (GetGroupDescription(cn, bG)) {
                                        mac.mcs[i] = 1;
                                        memset(&mac.mcs_desc[i], 0, MAX_DESCRIPTION_SZ);
                                        memcpy(&mac.mcs_desc[i], (void*)bG, minimum(bG.Size(), MAX_DESCRIPTION_SZ - 1));
                                    }
                                }
                            }
                        }
                        ldap_value_free_len(ppBerValue);
                    }
                }
                ldap_memfreeA(pAttribute);
                pAttribute = NULL;
                pAttribute = ldap_next_attributeA(m_pLdapConnection, pEntry, pBer);
            }
            if (pAttribute) {
                ldap_memfreeA(pAttribute);
            }
            if (pBer) {
                ber_free(pBer, 0);
            }
            bRC = true;
        }

        if (pSearchResult) {
            ldap_msgfree(pSearchResult);
        }

        return bRC;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::IsUserMemberOf(Buffer& bUPN, char* pcGroup)
{
    bool                    bRC = false;
    uint32_t                errorCode = LDAP_SUCCESS;
    char                    cFilter[1024];
    LDAPMessage* pSearchResult = NULL;
    char* dn = NULL;
    char* pMyAttributes[2];
    uint32_t               lRtn = LDAP_CONNECT_ERROR;

    std::unique_lock<std::mutex> mlock(mutexVar);

    if (!m_pLdapConnection)
        return false;

    try {
        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1, (int8_t*)"userPrincipalName=%s", (char*)bUPN);

        pMyAttributes[0] = (char*)"*";// "memberOf";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            (char*)m_QDN,
            LDAP_SCOPE_SUBTREE,//LDAP_SCOPE_ONELEVEL,//LDAP_SCOPE_SUBTREE,
            cFilter,
            pMyAttributes,
            0,
            &pSearchResult
        );
        if (lRtn != LDAP_SUCCESS)
            return false;

        lRtn = ldap_count_entries(m_pLdapConnection, pSearchResult);
        if (lRtn == 1) {
            LDAPMessage* pEntry = NULL;
            BerElement* pBer = NULL;
            char* pAttribute = NULL;

            pEntry = ldap_first_entry(m_pLdapConnection, pSearchResult);
            pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
            while (pAttribute) {
                if (strcmp(pAttribute, "memberOf") == 0) {
                    berval** ppBerValue = NULL;
                    uint32_t       iValue = 0;

                    ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                    if (ppBerValue != NULL) {
                        uint32_t z;
                        iValue = ldap_count_values_len(ppBerValue);//remember, the memberOf attribute can return multiple values for each group the user belongs to
                        for (z = 0; z < iValue; z++) {
                            if (pcGroup && strstr(ppBerValue[z]->bv_val, pcGroup)) {
                                bRC = true;
                            }
                        }
                        ldap_value_free_len(ppBerValue);
                    }
                }
                ldap_memfreeA(pAttribute);
                pAttribute = NULL;
                pAttribute = ldap_next_attributeA(m_pLdapConnection, pEntry, pBer);
            }
            if (pAttribute) {
                ldap_memfreeA(pAttribute);
            }
            if (pBer) {
                ber_free(pBer, 0);
            }
        }

        if (pSearchResult) {
            ldap_msgfree(pSearchResult);
        }

        return bRC;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::GetAccessControlForUser(Buffer& bUPN, Mandatory_AC& mac)
{
    bool bRc = false;
    std::unique_lock<std::mutex> mlock(mutexVar);
    try {
        if (FindUser(bUPN, mac)) {
            if ((strlen(mac.mls_desc) > 0) && (strlen(mac.mcs_desc[0]) > 0)) {
                bRc = true;
            }
        }
        return bRc;
    }
    catch (...) {
        return false;
    }
}

bool CLdap::GetMLSDescriptions(Buffer& b)
{
    int32_t i = 0;
    char cn[256];
    char desc[MAX_MLS_LEVEL][MAX_DESCRIPTION_SZ];

    std::unique_lock<std::mutex> mlock(mutexVar);

    try {
        memset(desc, 0, sizeof(desc));
        for (i = 0; i < MAX_MLS_LEVEL; i++) {
            Buffer bG;
            stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=l%d,OU=MLS,OU=MandatoryAccess,%s", i, (int8_t*)m_QDN);
            if (GetGroupDescription(cn, bG)) {
                memcpy(&desc[i], (void*)bG, minimum(bG.Size(), MAX_DESCRIPTION_SZ - 1));
            }
        }
        b.Append((void*)desc, sizeof(desc));

        return true;
    }
    catch (...) {
        b.Clear();
        return false;
    }
}

bool CLdap::GetMCSDescriptions(Buffer& b)
{
    int32_t i = 0;
    char cn[256];
    char desc[MAX_MCS_LEVEL][MAX_DESCRIPTION_SZ];

    std::unique_lock<std::mutex> mlock(mutexVar);

    try {
        memset(desc, 0, sizeof(desc));
        for (i = 0; i < MAX_MCS_LEVEL; i++) {
            Buffer bG;
            stringWrite((int8_t*)cn, sizeof(cn), (int8_t*)"CN=c%d,OU=MCS,OU=MandatoryAccess,%s", i, (int8_t*)m_QDN);
            if (GetGroupDescription(cn, bG)) {
                memcpy(&desc[i], (void*)bG, minimum(bG.Size(), MAX_DESCRIPTION_SZ - 1));
            }
        }
        b.Append((void*)desc, sizeof(desc));

        return true;
    }
    catch (...) {
        b.Clear();
        return false;
    }
}

bool CLdap::GetAttributes(Buffer& bUPN, Buffer& bAttributes)
{
    bool                    bRC = false;
    uint32_t                errorCode = LDAP_SUCCESS;
    char                    cFilter[1024];
    LDAPMessage* pSearchResult = NULL;
    char* dn = NULL;
    char* pMyAttributes[2];
    uint32_t               lRtn = LDAP_CONNECT_ERROR;

    std::unique_lock<std::mutex> mlock(mutexVar);

    if (!m_pLdapConnection)
        return false;

    try {
        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1, (int8_t*)"userPrincipalName=%s", (char*)bUPN);

        pMyAttributes[0] = (char*)"*";// "memberOf";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            (char*)m_QDN,
            LDAP_SCOPE_SUBTREE,//LDAP_SCOPE_ONELEVEL,//LDAP_SCOPE_SUBTREE,
            cFilter,
            pMyAttributes,
            0,
            &pSearchResult
        );
        if (lRtn != LDAP_SUCCESS)
            return false;

        lRtn = ldap_count_entries(m_pLdapConnection, pSearchResult);
        if (lRtn == 1) {
            LDAPMessage* pEntry = NULL;
            BerElement* pBer = NULL;
            char* pAttribute = NULL;

            pEntry = ldap_first_entry(m_pLdapConnection, pSearchResult);
            pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
            while (pAttribute) {
                berval** ppBerValue = NULL;
                ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                if (ppBerValue != NULL) {
                    if ((strcmp(pAttribute, "objectGUID") != 0) &&
                        (strcmp(pAttribute, "objectSid") != 0)) {
                        bAttributes.Append((void*)pAttribute, strlen(pAttribute));
                        bAttributes.Append((void*)LDAP_SEPS, strlen(LDAP_SEPS));
                        bAttributes.Append((void*)ppBerValue[0]->bv_val, ppBerValue[0]->bv_len);
                        bAttributes.EOLN();
                    }
                    ldap_value_free_len(ppBerValue);
                }
                ldap_memfreeA(pAttribute);
                pAttribute = NULL;
                pAttribute = ldap_next_attributeA(m_pLdapConnection, pEntry, pBer);
            }
            if (pAttribute) {
                ldap_memfreeA(pAttribute);
            }
            if (pBer) {
                ber_free(pBer, 0);
            }
            bRC = true;
        }

        if (pSearchResult) {
            ldap_msgfree(pSearchResult);
        }

        return bRC;
    }
    catch (...) {
        bAttributes.Clear();
        return false;
    }
}

bool CLdap::DownloadCertURI(char* cdp, Buffer& bCRL)
{
    bool bRC = false;
    LDAPMessage* pSearchResult = NULL;
    uint32_t lRtn = LDAP_CONNECT_ERROR;
    char* pMyAttributes[2];
    Buffer host;
    Buffer base;
    Buffer filter;
    Buffer attr;
    ULONG scope = 99999;

    std::unique_lock<std::mutex> mlock(mutexVar);

    if (!cdp) {
        return false;
    }

    if (!ParseURI(cdp, host, base, filter, attr, scope)) {
        return false;
    }
   
    try {
        pMyAttributes[0] = (char*)attr;
        pMyAttributes[1] = NULL;

        if (m_pLdapConnection) {
            lRtn = ldap_search_sA(
                m_pLdapConnection,
                (char*)base,
                scope,
                (char*)filter,
                pMyAttributes,
                0,
                &pSearchResult
            );

            if (lRtn != LDAP_SUCCESS) {
                return false;
            }

            lRtn = ldap_count_entries(m_pLdapConnection, pSearchResult);
            if (lRtn == 1) {//there should only be one combined crl
                LDAPMessage* pEntry = NULL;
                BerElement* pBer = NULL;
                char* pAttribute = NULL;

                pEntry = ldap_first_entry(m_pLdapConnection, pSearchResult);
                if (pEntry) {
                    pAttribute = ldap_first_attributeA(m_pLdapConnection, pEntry, &pBer);
                    if (pAttribute) {
                        berval** ppBerValue = NULL;
                        ppBerValue = ldap_get_values_lenA(m_pLdapConnection, pEntry, pAttribute);
                        if (ppBerValue != NULL) {
                            bCRL.Append(ppBerValue[0]->bv_val, ppBerValue[0]->bv_len);
                            ldap_value_free_len(ppBerValue);
                        }

                        ldap_memfreeA(pAttribute);
                        pAttribute = NULL;
                    }
                    if (pBer) {
                        ber_free(pBer, 0);
                    }
                    bRC = true;
                }
            }
            if (pSearchResult) {
                ldap_msgfree(pSearchResult);
            }
        }
        return bRC;
    }
    catch (...) {
        bCRL.Clear();
        return false;
    }
}

bool CLdap::Reconnect()
{
    return Disconnect() && Connect() && Bind();
}

bool CLdap::KeepAlive()
{
    uint32_t                errorCode = LDAP_SUCCESS;
    char                    cFilter[1024];
    char* pMyAttributes[5];
    LDAPMessage* pMsg = NULL;
    uint32_t                lRtn = LDAP_CONNECT_ERROR;

    //printf("keep alive start\n");

    std::unique_lock<std::mutex> mlock(mutexVar);

    if (!m_pLdapConnection) {
        return false;
    }

    try {
        memset(cFilter, 0, sizeof(cFilter));
        stringWrite((int8_t*)cFilter, sizeof(cFilter) - 1,
            (int8_t*)"(&(objectCategory=group)(distinguishedName=CN=l0,OU=MLS,OU=MandatoryAccess,%s))", (int8_t*)m_QDN);

        pMyAttributes[0] = (char*)"description";
        pMyAttributes[1] = NULL;

        lRtn = ldap_search_sA(
            m_pLdapConnection,
            (char*)m_QDN,
            LDAP_SCOPE_SUBTREE,//LDAP_SCOPE_ONELEVEL
            cFilter,
            pMyAttributes,
            0,
            &pMsg
        );

        if (pMsg) {
            ldap_msgfree(pMsg);
        }

        if (lRtn != LDAP_SUCCESS) {
#ifdef _DEBUG
            printf("LDAP keep alive failed!\n");
#endif
            return false;
        }
    }
    catch (...) {
        return false;
    }

    return true;
}
