/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include <Windows.h>
#include <wtsapi32.h>
#include <dpapi.h>
#include "MyLdap.h"
#include "MyKeyManager.h"
#include "KSPkey.h"
#include "x509class.h"
#include "NdacConfig.h"
#include "TLSContext.h"
#include "DilithiumKeyPair.h"

using namespace std;
using namespace ReiazDean;

extern Buffer* pPasswordBuffer;
EVP_PKEY* GenerateOrOpenRSA();
extern bool CreateFolders(Buffer bRoot);


extern BOOL
createServerCSR(
    char* subjUser,
    char* subjCntry,
    char* subjState,
    char* subjCity,
    char* subjOrg,
    char* subjUnit,
    char* subjUPN,
    Buffer& bCSR);

extern BOOL
base64Encode(
    uint8_t* pbDataIn,
    size_t dwLenIn,
    Buffer& bPEM);

NdacServerConfig::NdacServerConfig()
{
    myConfigItems.push_back(ConfigItems{ DOCUMENT_ROOT_FILE_LOCATION, "", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ KEY_STORAGE_PROVIDER, "", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ KSP_NEEDS_PASSWORD, "yes", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ LOCAL_UNIX_SOCKET_NAME, "MyUnixSocket", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ TLS_PORT_STRING, "1990", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ TLS_PRIV_KEY_FILE, "serverKey.key", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ TLS_PRIV_KEY_PWD_FILE, "serverKeyPwd.enc", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ TLS_CERTIFICATE_FILE, "serverCert.crt", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ TLS_CERT_FILE_REQ, "certReq.csr", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ TRUSTED_CA_FILE, "CAFile.crt", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ CRL_FILE, "combined.crl", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ REVOKED_CERT_SN_FILE, "RevokedCertSNs.dat", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ DILITHIUM_SECRET_FILE, "DilithiumSecret.dat", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ DILITHIUM_PUBLIC_FILE, "DilithiumPublic.dat", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ CLUSTER_MEMBERS_FILE, "ClusterMembers.conf", false, false, false, false });
    myConfigItems.push_back(ConfigItems{ SNMP_HOST_STRING, "127.0.0.1", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ SNMP_PORT_STRING, "0", false, false, false, true });//162 for real
    myConfigItems.push_back(ConfigItems{ SNMP_PRIV_PASSWORD, "password", true, false, false, true });
    myConfigItems.push_back(ConfigItems{ SNMP_AUTH_PASSWORD, "password", true, false, false, true });

    ReadConfigFile();
}

NdacServerConfig::~NdacServerConfig()
{
}

bool NdacServerConfig::CertMatchesPK(Buffer& bCert)
{
    char c[] = "This is a test!";
    Buffer bSig;
    Buffer bTmp;
    Buffer bHash;

    Sha256((uint8_t*)c, (uint32_t)strlen(c), bHash);
    if (RSA_Sign(GetWcharFromUtf8((char*)GetValue(TLS_PRIV_KEY_FILE), bTmp), (uint8_t*)bHash, bHash.Size(), (uint8_t*)*pPasswordBuffer, bSig)) {
        return RSA_VerifyBIO((uint8_t*)bCert, bCert.Size(), (uint8_t*)bHash, bHash.Size(), (uint8_t*)bSig, bSig.Size());
    }

    return false;
}

bool NdacServerConfig::DownloadCAcert(Buffer& bCert)
{
    Buffer bCAcert;
    Buffer aia;
    Certificate crt(bCert);
    Buffer bCACertFileName;
    GetValue(TRUSTED_CA_FILE, bCACertFileName);

    if (!crt.GetLdapAIA(aia)) {
        return false;
    }

    if (!CLdap::ProcessURI((char*)aia, bCAcert)) {
        return false;
    }

    if (bCAcert[0] == CONSTRUCTED_SEQUENCE) {
        Buffer bPEM;
        if (!base64Encode((uint8_t*)bCAcert, bCAcert.Size(), bPEM)) {
            return false;
        }
        bPEM.Prepend((void*)"-----BEGIN CERTIFICATE-----\n", strlen("-----BEGIN CERTIFICATE-----\n"));
        bPEM.Append((void*)"-----END CERTIFICATE-----\n", strlen("-----END CERTIFICATE-----\n"));
        bCAcert = bPEM;
    }

    if (saveToFile((int8_t*)bCACertFileName, (int8_t*)bCAcert, bCAcert.Size()) == 0) {
        return false;
    }

    return true;
}

bool NdacServerConfig::CertVerifiesWithBundle(Buffer& bCert)
{
    Buffer bCACertFileName;
    GetValue(TRUSTED_CA_FILE, bCACertFileName);
    return VerifyCertWithBundle((char*)bCACertFileName, bCert, bCert.Size());
}

bool NdacServerConfig::ChooseKSP(Buffer& bKSP)
{
    char  buf[256];
    uint32_t sz = 0;
    uint32_t count;
    uint32_t i;
    Buffer bProvs;
    std::vector<wchar_t*> provs;
    KSPkey::EnumProviders(bProvs);
    count = splitStringW((wchar_t*)bProvs, (wchar_t*)L"\n", provs);
    for (i = 0; i < count; i++) {
        printf("%u) %S\n", i, provs.at(i));
    }

    uint32_t j = 9999;
    while (j >= count) {
        memset(buf, 0, sizeof(buf));
        readConsole((char*)"for choice of KSP", buf, &sz);
        j = (uint32_t)atoi(buf);
    }

    bKSP.Clear();
    bKSP.Append(provs.at(j), wcslen(provs.at(j))*sizeof(wchar_t));
    bKSP.NullTerminate_w();

    return true;
}

bool NdacServerConfig::OpenKSP()
{
    Buffer bKSP = GetValueW(KEY_STORAGE_PROVIDER);
    if (bKSP.Size() > 0) {
        return true;
    }

    bKSP.Clear();
    if (ChooseKSP(bKSP)) {
        Buffer b;
        GetUtf8FromWchar((wchar_t*)bKSP, b);
        SetValue(KEY_STORAGE_PROVIDER, (char*)b);
        return (Save() ==  1);
    }

    return false;
}

bool NdacServerConfig::OpenOrCreateKSPkey()
{
    Buffer bKSP_w = GetValueW(KEY_STORAGE_PROVIDER);
        
    KSPkey ksp((WCHAR*)bKSP_w);
    if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)MY_SERVER_KSP_KEY_NAME, 0)) {
        return true;
    }
    else if (ERROR_SUCCESS == ksp.CreateKey((WCHAR*)MY_SERVER_KSP_KEY_NAME, NCRYPT_ALLOW_DECRYPT_FLAG)) {
        return true;
    }

    return false;
}

bool NdacServerConfig::KSPencrypt(Buffer& bSecret, Buffer& bEncSecret)
{
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);

    if (ERROR_SUCCESS == KSPkey::Encrypt((WCHAR*)bKSPw,(WCHAR*)MY_SERVER_KSP_KEY_NAME, bSecret, bEncSecret)) {
        return true;
    }

    return false;
}

bool NdacServerConfig::GenerateOrOpenDilithium()
{
    DilithiumKeyPair& dpk = TLSContext::GetDilithium();
    Buffer bSKfile = GetValue(DILITHIUM_SECRET_FILE);
    Buffer bPKfile = GetValue(DILITHIUM_PUBLIC_FILE);
    if (!pPasswordBuffer || (0 == pPasswordBuffer->Size())) {
        return false;
    }
    if (!dpk.Open((char*)bSKfile, (char*)bPKfile, (char*)*pPasswordBuffer)) {
        //fprintf(stdout, "%s\n", (char*)*pPasswordBuffer);
        dpk.Create();
        if (!dpk.Persist((char*)bSKfile, (char*)bPKfile, (char*)*pPasswordBuffer)) {
            printf("\nFailed to open or create the Dilithium key pair!\n");
            return false;
        }
        else {
            DilithiumKeyPair dpk2;
            printf("\nAbout to test the new Dilithium key pair!\n");
            if (dpk2.Open((char*)bSKfile, (char*)bPKfile, (char*)*pPasswordBuffer)) {
                char test[4096];
                Buffer bData, bSig;
                size_t sz = 0;
                memset(test, 'a', sizeof(test));
                bData.Append((void*)test, sizeof(test));
                sz = dpk2.Sign(bData, bSig);
                if (dpk2.Verify(bData, bSig)) {
                    printf("\nSuccess testing the new Dilithium key pair!\n");
                }
                else {
                    printf("\nFailed testing the new Dilithium key pair!\n");
                    return false;
                }
            }
            else {
                printf("\nFailed to open the new Dilithium key pair!\n");
                return false;
            }
        }

        printf("\nSuccess creating and persisting the Dilithium key pair!\n");
        return true;
    }
    
    printf("\nSuccess opening the Dilithium key pair!\n");

    return true;
}

void NdacServerConfig::ReadConfigFile() {
    return DoReadConfigFile(SERVER_CONF_FILE);
}

uint8_t NdacServerConfig::Save() {
    return DoSave(SERVER_CONF_FILE);
}

bool NdacServerConfig::Prerequisites()
{
    uint32_t sz = 0;
    EVP_PKEY* pubkey = nullptr;
    Buffer bFile(myFilePath);

    if (!CreateDirectoryA((char*)bFile, 0)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            return 0;
        }
    }

    //Open the configured KSP. If none is configured, select one that interfaces with a HSM or smartcard token.
    if (!OpenKSP()) {
        return false;
    }

    //Open or create a KSP managed hardware RSA asymmetric key pair
    if (!OpenOrCreateKSPkey()) {
        return false;
    }

    //Next, generate or open the RSA key pair and return the public portion
    //this RSA key pair is used for TLS and the private key will persist on the servers file system.
    //however, it will be encrypted with the HSM or smartcard RSA + AES.
    pubkey = GenerateOrOpenRSA();
    if (!pubkey) {
        return false;
    }

    EVP_PKEY_free(pubkey);

    //Next, generate or open the Dilithium key pair.
    //this Dilithium key pair is used for Perfect Forward Secrecy and the private key will persist on the servers file system.
    //however, it will be encrypted with the HSM or smartcard RSA + AES.
    if (!GenerateOrOpenDilithium()) {
        return false;
    }

    return true;
}

#define NUM_SUBJECTS 7
#define SUBJECT_SZ 256
bool NdacServerConfig::InitiateServerCSR(char* csrFileName)
{
    Buffer bDNS;
    Buffer bCSR;
    char subjects[NUM_SUBJECTS][SUBJECT_SZ] = {
    "Authorization Service",
    "CA",
    "Ontario",
    "Ottawa",
    "RDC Inc.",
    "Engineering",
    "yourdomain.com" };

    char prompts[NUM_SUBJECTS][SUBJECT_SZ] = {
    "Subject User Name",
    "Subject Country",
    "Subject Province/State",
    "Subject City",
    "Subject Organization",
    "Subject Organization Unit",
    "DNS suffix for the Subject Alternative Name" };

    bool modifiable[NUM_SUBJECTS] = {
    false,
    true,
    true,
    true,
    true,
    true,
    false };

    GetDomainName(bDNS);
    if (bDNS.Size() > 0) {
        bDNS.NullTerminate();
        stringWrite((int8_t*)subjects[NUM_SUBJECTS - 1], SUBJECT_SZ, (int8_t*)"%s", (char*)bDNS);
    }

    printf("%s\n", subjects[NUM_SUBJECTS - 1]);
    for (int i = 0; i < NUM_SUBJECTS; i++) {
        if (modifiable[i]) {
            uint32_t sz = SUBJECT_SZ;
            char prompt[SUBJECT_SZ * 2];
            stringWrite((int8_t*)prompt, sizeof(prompt), (int8_t*)"%s[%s]", (char*)prompts[i], (char*)subjects[i]);
            readConsole((char*)prompt, (char*)subjects[i], &sz);
        }
    }


    if (createServerCSR(subjects[0], subjects[1], subjects[2], subjects[3], subjects[4], subjects[5], subjects[6], bCSR)) {
        if (saveToFile((int8_t*)csrFileName, (int8_t*)bCSR, bCSR.Size()) == 1) {
            printf("\nCSR successfully saved to %s\nContents = \n%s\n", csrFileName, (char*)bCSR);
            return true;
        }
        else {
            printf("Failed to save CSR data to %s!\n", csrFileName);
            return false;
        }
    }

    return false;
}

bool NdacServerConfig::DeployCACertificate(char* pcCert)
{
    Buffer bServerCertFileName = GetValue(TLS_CERTIFICATE_FILE);
    Buffer bCAcertFileName = GetValue(TRUSTED_CA_FILE);
    Buffer bCert;

    if (!Prerequisites()) {
        return false;
    }

    if (!pPasswordBuffer || (0 == pPasswordBuffer->Size())) {
        return false;
    }

    if (readFile((char*)bServerCertFileName, bCert) <= 0) {
        printf("Invalid server certificate!\n");
        return false;
    }

    if (CertFileType((char*)bServerCertFileName) == CERT_FILE_TYPE_PEM) {
        uint32_t szCert = bCert.Size();
        PEMcert_to_DERcert(bCert, szCert);
    }

    if (!CertMatchesPK(bCert)) {
        printf("Private key mismatch with certificate!\n");
        return false;
    }

    if (pcCert) {
        if (!CopyFileA((char*)pcCert, (char*)bCAcertFileName, TRUE)) {
            printf("Failed to save CA certificate %s!\n", (char*)bCAcertFileName);
            return false;
        }
    }
    else {
        if (DownloadCAcert(bCert)) {
            printf("Successfully downloaded CA certificate from AIA information!\n");
        }
        else {
            printf("Failed to download CA certificate from AIA information!\n");
            return false;
        }
    }

    if (!CertVerifiesWithBundle(bCert)) {
        printf("Bundle chain verification failed!\n");
        return false;
    }
    else {
        printf("Success saving CA certificate %s!\n", (char*)bCAcertFileName);
        return true;
    }

    return false;
}

bool NdacServerConfig::DeployServerCertificate(char* pcP7bFile)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    Buffer bServerCertFileName = GetValue(TLS_CERTIFICATE_FILE);
    Buffer bCAcertFileName = GetValue(TRUSTED_CA_FILE);
    Buffer chain[3];

    if (!pcP7bFile) {
        return false;
    }

    if (!Prerequisites()) {
        return false;
    }

    if (!pPasswordBuffer || (0 == pPasswordBuffer->Size())) {
        return false;
    }

    try {
        Buffer bFile;
        GetWcharFromUtf8(pcP7bFile, bFile);
        BOOL ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            (wchar_t*)bFile,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY | CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
            0,
            NULL,
            NULL,
            NULL,
            &hStore,
            &hMsg,
            NULL
        );

        if (ok && hStore) {
            Buffer bCert;
            PCCERT_CONTEXT pCert = NULL;
            
            while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
                Buffer bSubj, bIss;
                Buffer b((char*)pCert->pbCertEncoded, pCert->cbCertEncoded);
                Certificate cert(b);
                cert.GetSubject(bSubj);
                cert.GetIssuer(bIss);
                if (strstr((char*)bSubj, (char*)"Authorization Service")) {
                    chain[0] = b;
                }
                else if ((bSubj.Size() == bIss.Size()) && (memcmp(bSubj, bIss, bIss.Size()) == 0)) {//self signed root CA cert
                    chain[2] = b;//2 holds the root
                    chain[1] = b; //1 holds the intermediate issuing
                }
                else {
                    chain[1] = b; //must be the issuing CA cert
                }
            }
            CertCloseStore(hStore, 0);
            hStore = NULL;
            if (hMsg) {
                CryptMsgClose(hMsg);
                hMsg = NULL;
            }

            bCert = chain[0];
            if (bCert.Size() == 0) {
                printf("Invalid server certificate!\n");
                return false;
            }

            if (!CertMatchesPK(bCert)) {
                printf("Private key mismatch with certificate!\n");
                return false;
            }
            else {
                Buffer bPEM;
                if (!base64Encode((uint8_t*)bCert, bCert.Size(), bPEM)) {
                    return false;
                }
                bPEM.Prepend((void*)"-----BEGIN CERTIFICATE-----\n", strlen("-----BEGIN CERTIFICATE-----\n"));
                bPEM.Append((void*)"-----END CERTIFICATE-----\n", strlen("-----END CERTIFICATE-----\n"));
                if (saveToFile((int8_t*)bServerCertFileName, (int8_t*)bPEM, bPEM.Size()) == 0) {
                    printf("Failed to save server certificate %s!\n", (char*)bServerCertFileName);
                    return false;
                }
                else {
                    bPEM.Clear();
                    bCert = chain[1];
                    if (bCert.Size() == 0) {
                        printf("Invalid CA certificate!\n");
                        return false;
                    }

                    if (!base64Encode((uint8_t*)bCert, bCert.Size(), bPEM)) {
                        return false;
                    }
                    bPEM.Prepend((void*)"-----BEGIN CERTIFICATE-----\n", strlen("-----BEGIN CERTIFICATE-----\n"));
                    bPEM.Append((void*)"-----END CERTIFICATE-----\n", strlen("-----END CERTIFICATE-----\n"));
                    if (saveToFile((int8_t*)bCAcertFileName, (int8_t*)bPEM, bPEM.Size()) == 0) {
                        printf("Failed to save CA certificate %s!\n", (char*)bCAcertFileName);
                        return false;
                    }
                    printf("Success deploying server certificate %s and CA certificate %s!\n", (char*)bServerCertFileName, (char*)bCAcertFileName);
                    return true;
                }
            }
        }
    }
    catch (...) {
        if (hStore) {
            CertCloseStore(hStore, 0);
            hStore = NULL;
        }
        if (hMsg) {
            CryptMsgClose(hMsg);
            hMsg = NULL;
        }
        printf("Failed to save server certificate %s!\n", (char*)bServerCertFileName);
        return false;
    }

    return false;
}

bool NdacServerConfig::GenerateServerCSR()
{
    Buffer bCSRFileName;
    bCSRFileName = GetValue(TLS_CERT_FILE_REQ);

    if (!Prerequisites()) {
        return false;
    }

    return InitiateServerCSR((char*)bCSRFileName);
}

#define NUM_CFG_FILES 6
bool NdacServerConfig::FileChecks()
{
    Buffer bFile(myFilePath);
    char MyFiles[NUM_CFG_FILES][32] = {
   "\\serverKey.key",
   "\\serverKeyPwd.enc",
   "\\serverCert.crt",
   "\\CAFile.crt",
   "\\DilithiumSecret.dat",
   "\\DilithiumPublic.dat" };

    for (int i = 0; i < NUM_CFG_FILES; i++) {
        struct _stat stB;
        Buffer bFile(myFilePath);
        bFile.Append((void*)MyFiles[i], strlen(MyFiles[i]));
        bFile.NullTerminate();
        if (_stat((char*)bFile, &stB) != 0) {
            printf("\nError, %s does not exist. Please first create the TLS key and certificate files!\n", (char*)bFile);
            return false;
        }
        if (stB.st_size == 0) {
            printf("\nError, %s is an epmty file. Please first create the TLS key and certificate files!\n", (char*)bFile);
            return false;
        }
    }

    return true;
}

bool NdacServerConfig::Configure()
{
    char  buf[1024];
    uint32_t sz = 0;

    if (!FileChecks()) {
        return false;
    }

    if (!Prerequisites()) {
        return false;
    }

    if (!pPasswordBuffer || (0 == pPasswordBuffer->Size())) {
        return false;
    }

    for (const auto& tup : myConfigItems) {
        if (tup.bUserModifiable) {
            std::string sKey = tup.sKey;
            std::string p = sKey + "[" + (char*)GetValue(sKey.c_str()) + "]";
            memset(buf, 0, sizeof(buf));
            sz = 0;
            if ((sKey.compare(SNMP_PRIV_PASSWORD) == 0) || (sKey.compare(SNMP_AUTH_PASSWORD) == 0)) {
                while (1) {
                    char  repeat[256];
                    memset(repeat, 0, sizeof(repeat));
                    memset(buf, 0, sizeof(buf));
                    p = sKey + "[***************]";
                    std::cout << "\nWhat is the " + p + ": ";
                    readPassword(buf, sizeof(buf));
                    if (strlen(buf) < 9) {
                        std::cout << "\n\nERROR: Password is too short! Minimum of 9 characters required!\n";
                        continue;
                    }
                    std::cout << "\nConfirm Data For " + p + ": ";
                    readPassword(repeat, sizeof(repeat));
                    if (strcmp(buf, repeat) == 0) {
                        break;
                    }
                    std::cout << "\n\nERROR: Inupts dont' match!\n";
                }
            }
            else {
                readConsole((char*)p.c_str(), buf, &sz);
            }
            std::cout << "\n";
            if (strlen(buf) < 1) {
                continue;
            }

            try {
                if (tup.bEncrypted) {
                    Buffer encrypted;
                    Buffer hex;
                    Buffer bHash;

                    Sha384((uint8_t*)*pPasswordBuffer, pPasswordBuffer->Size(), bHash);
                    AES_CBC_Encrypt((uint8_t*)bHash, (uint8_t*)bHash + 32, (uint8_t*)buf, (uint32_t)strlen(buf), encrypted);
                    hexEncode((uint8_t*)encrypted, encrypted.Size(), hex);
                    hex.NullTerminate();
                    SetValue(sKey, (char*)hex);
                }
                else if (sKey.compare(DOCUMENT_ROOT_FILE_LOCATION) == 0) {
                    Buffer bRoot;
                    bRoot.Append((char*)buf, strlen(buf));
                    bRoot.Append((char*)"\\classified", strlen((char*)"\\classified"));
                    bRoot.NullTerminate();
                    SetValue(sKey, (char*)bRoot);
                    if (!CreateFolders(bRoot)) {
                        //printf("Failed to create the document root folder within \"%s\"\n", (char*)buf);
                        std::cout << "\nFailed to create the document root folder within " + string(buf) + "\n";
                        return false;
                    }
                }
                else {
                    SetValue(sKey, buf);
                }
            }
            catch (...) {
                std::cout << "\n\nFAILED CONFIGURATION!!\n";
                return false;
            }
        }
    }

    return true;
}
