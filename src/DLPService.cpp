/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "winsock2.h"
#include <Ws2tcpip.h>
#include <afunix.h>
#include "strsafe.h"
#include <dsgetdc.h>
#include <Lm.h>
#include <conio.h>
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#include <time.h>
#include <iostream>
#include <thread>
#include "LocalClient.h"
#include "ECKeyPair.h"
#include "Utils.h"
#include "Buffer.h"
#include "NdacConfig.h"
#include "MyLdap.h"
#include "MyKeyManager.h"
#include "KSPkey.h"
#include "RSAPublicKey.h"
#include "x509class.h"
#include "crlClass.h"
#include "crlManager.h"
#include "threadPool.h"
#include "rdc_events.h"
#include "OsslClientHelper.h"
#include "clusterServiceManager.h"
#include "SnmpTrap.h"
#include "SequenceReader.h"
#include "Authorization.h"

using namespace std;
using namespace ReiazDean;

extern VOID SvcInstall(TCHAR* uName, TCHAR* uPwd);
extern VOID __stdcall DoDeleteSvc();
extern VOID WINAPI SvcCtrlHandler(DWORD);
extern VOID WINAPI SvcMain(DWORD, LPTSTR*);

//All the static and global buffers here for orderly creation and destruction
//***************************************************************************
MemoryPoolManager  Buffer::MyMemPoolManager;
CLdap CLdap::TheCLdap;//the constructor creates Buffers
NdacServerConfig NdacServerConfig::TheNdacServerConfig;
MyKeyManager MyKeyManager::TheMyKeyManager;
ClusterServiceManager ClusterServiceManager::TheClusterServiceManager;
SSL_CTX* TLSServerContext::s_ctx = TLSServerContext::CreateContext();
//csr.cpp
Buffer SubjCntry;
Buffer SubjState;
Buffer SubjCity;
Buffer SubjOrg;
Buffer SubjUnit;
Buffer SubjUser;
Buffer SubjAltName;
Buffer SubjEmail;
Buffer Password;
Buffer Extensions;
Buffer Signature;
//end csr.cpp
Buffer KSPkey::Password;
Buffer CRLManager::s_LatestCRL;
static Buffer PasswordBuffer;
Buffer* pPasswordBuffer = &PasswordBuffer;
Buffer TLSServerContext::s_PrivateKeyPassword;
ECKeyPair TLSServerContext::s_ECKeyPair;
DilithiumKeyPair TLSContext::s_DilithiumKeyPair;
Buffer SnmpTrap::s_PrivPwd;
Buffer SnmpTrap::s_AuthPwd;
//***************************************************************************

HANDLE ghEventSource = NULL;

std::atomic<BOOL> ApplicationStopped = FALSE;
std::atomic<int> NumWorkersRunning = 0;

bool doTlsServerPassword(Buffer& bPwd) {
    if (doTlsServerPasswordEx(bPwd)) {
        PasswordBuffer = bPwd;
        return true;
    }

    return false;
}

void* StartLocalService(void* args)
{
    LocalServer   ls(ServiceType::SVC_TYPE_AUTH_SERVICE);
    return 0;
}

void ErrorString(LPCTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    //ExitProcess(dw);
}

BOOL  RegisterMessages()
{
    HKEY    hKey = 0;
    DWORD   dwDisposition = 0;
    DWORD   dwSize = sizeof(DWORD);
    long    lRet;
    WCHAR   wcFile[] = L"%SystemRoot%\\System32\\EventCreate.exe";
    DWORD   dwTypes = 7;
    DWORD   dwSrc = 1;
    WCHAR   REG_KEY_RDC_INC[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\CustomLog\\RDCInc_Auth_Service";

    lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        REG_KEY_RDC_INC,
        0, KEY_ALL_ACCESS, &hKey);

    if (lRet != ERROR_SUCCESS)
    {
        lRet = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            REG_KEY_RDC_INC,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hKey,
            &dwDisposition);
    }

    if (lRet == ERROR_SUCCESS) {
        lRet = RegSetValueExW(hKey, (WCHAR*)L"EventMessageFile", 0, REG_EXPAND_SZ, (LPBYTE)wcFile, (DWORD)wcslen(wcFile) * sizeof(WCHAR));
    }

    if (lRet == ERROR_SUCCESS) {
        lRet = RegSetValueExW(hKey, (WCHAR*)L"CustomSource", 0, REG_DWORD, (LPBYTE)&dwSrc, sizeof(DWORD));
    }

    if (lRet == ERROR_SUCCESS) {
        lRet = RegSetValueExW(hKey, (WCHAR*)L"TypeSupported", 0, REG_DWORD, (LPBYTE)&dwTypes, sizeof(DWORD));
    }

    if (hKey) {
        RegCloseKey(hKey);
    }

    return (lRet == ERROR_SUCCESS);
}

void
ServiceReportEvent(
    LPTSTR szMessage,
    WORD dwCategory,
    WORD dwType,
    DWORD dwErr)
{
    LPCWSTR lpszStrings[2];
    WCHAR buf[256];

    if (NULL != ghEventSource)
    {
        DWORD dwID = dwErr & 0x00001111;
        StringCchPrintfW(buf, 256, L"\n%S processed with status: %d", szMessage, dwID);

        lpszStrings[0] = buf;
        lpszStrings[1] = buf;

        ReportEventW(
            ghEventSource,       // event log handle
            dwType,              // event type
            dwCategory,          // event category
            dwID,               // event identifier
            NULL,                // no security identifier
            1,                   // size of lpszStrings array
            0,                   // no binary data
            lpszStrings,         // array of strings
            NULL);               // no binary data
    }

}

BOOL MyCreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    if (!lpPathName) {
        return FALSE;
    }

    if (strlen(lpPathName) > MY_MAX_PATH) {
        fprintf(stdout, "\nThe size of %s exceeds %d characters. Please reconsider your file share layout and the MLS/MCS description sizes in AD!\n",
            lpPathName, MY_MAX_PATH);
        exit(-1);

    }

    return CreateDirectory(lpPathName, lpSecurityAttributes);
}

bool CreateFolders(Buffer bRoot)
{
    CLdap& mCLdap = CLdap::GetInstance();
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    int32_t i = 0;
    int32_t j = 0;

    Buffer bMLS;
    char mls_desc[MAX_MLS_LEVEL][MAX_DESCRIPTION_SZ];
    Buffer bMCS;
    char mcs_desc[MAX_MCS_LEVEL][MAX_DESCRIPTION_SZ];

    if (!mCLdap.Connect()) {
        return false;
    }

    if (!mCLdap.Bind()) {
        return false;
    }

    if (!MyCreateDirectoryA((char*)bRoot, 0)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            return false;
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Temp");
        if (!MyCreateDirectoryA((char*)temp_folder, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Drafts");
        if (!MyCreateDirectoryA((char*)temp_folder, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Published");
        if (!MyCreateDirectoryA((char*)temp_folder, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Declassified");
        if (!MyCreateDirectoryA((char*)temp_folder, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
    }

    if (!mCLdap.GetMCSDescriptions(bMCS)) {
        return false;
    }
    memcpy(mcs_desc, (void*)bMCS, bMCS.Size());

    if (!mCLdap.GetMLSDescriptions(bMLS)) {
        return false;
    }
    memcpy(mls_desc, (void*)bMLS, bMLS.Size());

    for (i = 0; i < MAX_MCS_LEVEL; i++) {
        if (strlen(mcs_desc[i]) > 0) {
            char mcs_folder[MAX_NAME];
            memset(mcs_folder, 0, sizeof(mcs_folder));
            stringWrite((int8_t*)mcs_folder, sizeof(mcs_folder),
                (int8_t*)"%s\\Drafts\\%s", (int8_t*)bRoot, (int8_t*)mcs_desc[i]);
            if (!MyCreateDirectoryA((char*)mcs_folder, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }
            for (j = 0; j < MAX_MLS_LEVEL; j++) {
                if (strlen(mls_desc[j]) > 0) {
                    char mls_folder[MAX_NAME];
                    memset(mls_folder, 0, sizeof(mls_folder));
                    stringWrite((int8_t*)mls_folder, sizeof(mls_folder),
                        (int8_t*)"%s\\%s", (int8_t*)mcs_folder, (int8_t*)mls_desc[j]);
                    if (!MyCreateDirectoryA((char*)mls_folder, 0)) {
                        if (GetLastError() != ERROR_ALREADY_EXISTS) {
                            return false;
                        }
                    }
                }
            }
        }
    }

    for (i = 0; i < MAX_MCS_LEVEL; i++) {
        if (strlen(mcs_desc[i]) > 0) {
            char mcs_folder[MAX_NAME];
            memset(mcs_folder, 0, sizeof(mcs_folder));
            stringWrite((int8_t*)mcs_folder, sizeof(mcs_folder),
                (int8_t*)"%s\\Published\\%s", (int8_t*)bRoot, (int8_t*)mcs_desc[i]);
            if (!MyCreateDirectoryA((char*)mcs_folder, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }
            for (j = 0; j < MAX_MLS_LEVEL; j++) {
                if (strlen(mls_desc[j]) > 0) {
                    char mls_folder[MAX_NAME];
                    memset(mls_folder, 0, sizeof(mls_folder));
                    stringWrite((int8_t*)mls_folder, sizeof(mls_folder),
                        (int8_t*)"%s\\%s", (int8_t*)mcs_folder, (int8_t*)mls_desc[j]);
                    if (!MyCreateDirectoryA((char*)mls_folder, 0)) {
                        if (GetLastError() != ERROR_ALREADY_EXISTS) {
                            return false;
                        }
                    }
                }
            }
        }
    }

    for (i = 0; i < MAX_MCS_LEVEL; i++) {
        if (strlen(mcs_desc[i]) > 0) {
            char mcs_folder[MAX_NAME];
            memset(mcs_folder, 0, sizeof(mcs_folder));
            stringWrite((int8_t*)mcs_folder, sizeof(mcs_folder),
                (int8_t*)"%s\\Declassified\\%s", (int8_t*)bRoot, (int8_t*)mcs_desc[i]);
            if (!MyCreateDirectoryA((char*)mcs_folder, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }
        }
    }

    return true;
}

bool DirectoryValidatesA(const char* pcPath)
{
    Buffer bErr;
    char e1[] = "Folder name size exceeds MY_MAX_PATH(180 characters): ";
    char e2[] = "Non existent folder : ";

    if (!pcPath) {
        return false;
    }

    bErr.Append((void*)pcPath, strlen((char*)pcPath));
    bErr.NullTerminate();

    if (DirectoryExistsA(pcPath)) {
        if (strlen(pcPath) <= MY_MAX_PATH) {
            return true;
        }
        else {
            bErr.Prepend((void*)e1, strlen((char*)e1));
        }
    }
    else {
        bErr.Prepend((void*)e2, strlen((char*)e2));
    }

    ServiceReportEvent((char*)bErr, LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_ERROR, MSG_FAILED);

    return false;
}

bool ValidateFolders()
{
    CLdap& mCLdap = CLdap::GetInstance();
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    int32_t i = 0;
    int32_t j = 0;

    Buffer bMLS;
    char mls_desc[MAX_MLS_LEVEL][MAX_DESCRIPTION_SZ];
    Buffer bMCS;
    char mcs_desc[MAX_MCS_LEVEL][MAX_DESCRIPTION_SZ];

    Buffer bRoot = nc.GetValue(DOCUMENT_ROOT_FILE_LOCATION);
    if (bRoot.Size() == 0) {
        return false;
    }

    if (!DirectoryValidatesA((char*)bRoot)) {
        return false;
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Temp");
        if (!DirectoryValidatesA((char*)temp_folder)) {
            return false;
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Drafts");
        if (!DirectoryValidatesA((char*)temp_folder)) {
            return false;
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Published");
        if (!DirectoryValidatesA((char*)temp_folder)) {
            return false;
        }
    }

    {
        char temp_folder[MAX_NAME];
        memset(temp_folder, 0, sizeof(temp_folder));
        stringWrite((int8_t*)temp_folder, sizeof(temp_folder),
            (int8_t*)"%s\\%s", (int8_t*)bRoot, (int8_t*)"Declassified");
        if (!DirectoryValidatesA((char*)temp_folder)) {
            return false;
        }
    }


    if (!mCLdap.GetMCSDescriptions(bMCS)) {
        ServiceReportEvent((char*)"Unable to query AD for MCS  group descriptions!", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_ERROR, MSG_FAILED);
        return false;
    }
    memcpy(mcs_desc, (void*)bMCS, bMCS.Size());

    if (!mCLdap.GetMLSDescriptions(bMLS)) {
        ServiceReportEvent((char*)"Unable to query AD for MLS  group descriptions!", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_ERROR, MSG_FAILED);
        return false;
    }
    memcpy(mls_desc, (void*)bMLS, bMLS.Size());

    for (i = 0; i < MAX_MCS_LEVEL; i++) {
        if (strlen(mcs_desc[i]) > 0) {
            char mcs_folder[MAX_NAME];
            memset(mcs_folder, 0, sizeof(mcs_folder));
            stringWrite((int8_t*)mcs_folder, sizeof(mcs_folder),
                (int8_t*)"%s\\Drafts\\%s", (int8_t*)bRoot, (int8_t*)mcs_desc[i]);
            if (!DirectoryValidatesA((char*)mcs_folder)) {
                return false;
            }
            for (j = 0; j < MAX_MLS_LEVEL; j++) {
                if (strlen(mls_desc[j]) > 0) {
                    char mls_folder[MAX_NAME];
                    memset(mls_folder, 0, sizeof(mls_folder));
                    stringWrite((int8_t*)mls_folder, sizeof(mls_folder),
                        (int8_t*)"%s\\%s", (int8_t*)mcs_folder, (int8_t*)mls_desc[j]);
                    if (!DirectoryValidatesA((char*)mls_folder)) {
                        return false;
                    }
                }
            }
        }
    }

    for (i = 0; i < MAX_MCS_LEVEL; i++) {
        if (strlen(mcs_desc[i]) > 0) {
            char mcs_folder[MAX_NAME];
            memset(mcs_folder, 0, sizeof(mcs_folder));
            stringWrite((int8_t*)mcs_folder, sizeof(mcs_folder),
                (int8_t*)"%s\\Published\\%s", (int8_t*)bRoot, (int8_t*)mcs_desc[i]);
            if (!DirectoryValidatesA((char*)mcs_folder)) {
                return false;
            }
            for (j = 0; j < MAX_MLS_LEVEL; j++) {
                if (strlen(mls_desc[j]) > 0) {
                    char mls_folder[MAX_NAME];
                    memset(mls_folder, 0, sizeof(mls_folder));
                    stringWrite((int8_t*)mls_folder, sizeof(mls_folder),
                        (int8_t*)"%s\\%s", (int8_t*)mcs_folder, (int8_t*)mls_desc[j]);
                    if (!DirectoryValidatesA((char*)mls_folder)) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

bool CheckPassword(char* bUser, char* bPwd, char* bSuffix)
{
    HANDLE hToken = NULL;
    BOOL result = LogonUserA(bUser, bSuffix, bPwd, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &hToken);

    if (result) {
        CloseHandle(hToken);
        return true;
    }

    printf("\nError, bad password!\n");
    return false;
}

int DoWindowsService(int argc, char** argv)
{
    if (argc < 4) {
        printf("\nUsage: %s ServiceConfig WinService <Install|Uninstall]\n", argv[0]);
        return -1;
    }
    else if (strcmp(argv[3], "Install") == 0) {
        if (argc < 5) {
            printf("\nUsage: %s ServiceConfig WinService Install <AD_user_name>\n", argv[0]);
            return -1;
        }
        else {
            Buffer bDNS;
            GetDomainName(bDNS);

            if (bDNS.Size() > 0) {
                char user[128];
                char pwd[128];
                bDNS.NullTerminate();
                stringWrite((int8_t*)user, sizeof(user), (int8_t*)"%s@%s", argv[4], (char*)bDNS);
                printf("\nInput password for %s {Just hit [Enter] if using a gMSA):", user);
                readPassword(pwd, 128);
                if (strlen(pwd) == 0) {
                    SvcInstall(user, NULL);
                }
                else {
                    if (CheckPassword(argv[4], pwd, (char*)bDNS)) {
                        SvcInstall(user, (char*)pwd);
                    }
                }
            }
        }
    }
    else if (strcmp(argv[3], "Uninstall") == 0) {
        DoDeleteSvc();
    }

    return 0;
}

int DoServiceConfig(int argc, char** argv)
{
    NdacServerConfig& nc = NdacServerConfig::GetInstance();

    if (argc < 3) {
        printf("\nUsage: %s ServiceConfig [Finish  | CreateCSR | DeployServerCert <certname> | DeployCACert <certname> | WinService <Install|Uninstall]\n",
            argv[0]);
        return -1;
    }
    else if (strcmp(argv[2], "Finish") == 0) {
        if (nc.Configure()) {
            if (nc.Save() != 1) {
                printf("\nFailed to save configuration data!\n");
            }
            else {
                RegisterMessages();
            }
        }
    }
    else if (strcmp(argv[2], "CreateCSR") == 0) {
        nc.GenerateServerCSR();
    }
    else if (strcmp(argv[2], "DeployServerCert") == 0) {
        if (argc >= 4) {
            nc.DeployServerCertificate(argv[3]);
        }
        else {
            printf("\nUsage: %s ServiceConfig DeployServerCert <certname>\n", argv[0]);
        }
    }
    else if (strcmp(argv[2], "DeployCACert") == 0) {
        if (argc >= 4) {
            nc.DeployCACertificate(argv[3]);
        }
        else {
            nc.DeployCACertificate(nullptr);
        }
    }
    else if (strcmp(argv[2], "WinService") == 0) {
        DoWindowsService(argc, argv);
    }
    else {
        printf("\nUsage: %s ServiceConfig [Finish  | CreateCSR | DeployServerCert <certname> | DeployCACert <certname> | WinService <Install|Uninstall]\n",
            argv[0]);
        return -1;
    }

    return 0;
}

bool IsServiceAlreadyRunning()
{
    LocalClient lc;
    if (lc.Established()) {
        return true;
    }
    else {
        try {
            Buffer bSockName;
            NdacServerConfig& scfg = NdacServerConfig::GetInstance();
            scfg.GetValue(LOCAL_UNIX_SOCKET_NAME, bSockName);
            bSockName.NullTerminate();
            _unlink((char*)bSockName);
        }
        catch (...) {
            return false;
        }
    }
    return false;
}

int main(int argc, char** argv)
{
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    WSADATA     WSAData = { 0 };
    if (FAILED(WSAStartup(MAKEWORD(2, 2), &WSAData))) {
        exit(-1);
    }

    MyKeyManager& mykey = MyKeyManager::GetInstance();
    CLdap& mCLdap = CLdap::GetInstance();
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();
    ClusterServiceManager& csm = ClusterServiceManager::GetInstance();

    Buffer::Startup();
    threadPool::Initialize();
    threadPool::queueThread((void*)OsslClientHelper::Initialize, 0);
    csm.LoadMembers();

    {
        DilithiumKeyPair& dpk = TLSContext::GetDilithium();
        Buffer bPKfile = scfg.GetValue(DILITHIUM_PUBLIC_FILE);
        dpk.ReadPublic((char*)bPKfile);
    }

    if (!IsDomainJoined()) {
#ifndef _DEBUG
        return 0;
#endif
    }

    ghEventSource = RegisterEventSource(NULL, SVCNAME);

    if (argc == 1) {
        if (IsServiceAlreadyRunning()) {
            exit(-1);
        }
        else {
            SERVICE_TABLE_ENTRY DispatchTable[] =
            {
                { (TCHAR*)SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
                { NULL, NULL }
            };

            CRLManager::Initialize();
            // This call returns when the service has stopped. 
            // The process should simply terminate when the call returns.
            if (!StartServiceCtrlDispatcher(DispatchTable))
            {
                ServiceReportEvent((TCHAR*)"StartServiceCtrlDispatcher FAILED", LOCAL_SERVICE_CATEGORY, STATUS_SEVERITY_ERROR, MSG_FAILED);
            }
        }
    }
    else if (strcmp(argv[1], "StartTLS") == 0) {
        SECURITY_STATUS ss = NTE_FAIL;
        char pwd[128];
        Buffer bKSPw = scfg.GetValueW(KEY_STORAGE_PROVIDER);
        KSPkey ksp((WCHAR*)bKSPw);

        printf("\nInput HSM password:");
        readPassword(pwd, 128);
        ss = ksp.OpenKeySilently((WCHAR*)MY_SERVER_KSP_KEY_NAME, 0, pwd);
        if (ss == ERROR_SUCCESS) {
            Buffer bSecrets;
            if (LoadSecrets(ksp, bSecrets)) {
                LocalClient lc;
                lc.SendToLocal(Commands::CMD_SEND_TLS_PK_PASSWD, bSecrets);
            }
        }
    }
    else if (strcmp(argv[1], "ServiceConfig") == 0) {
        if (IsUserDomainAdmin()) {
            DoServiceConfig(argc, argv);
        }
        else {
            printf("\nError, user is not a domain Admin!\n");
        }
    }
    else if (strcmp(argv[1], "CreateCluster") == 0) {
        if (IsUserDomainAdmin()) {
            csm.CreateCluster();
        }
        else {
            printf("\nError, user is not a domain Admin!\n");
        }
    }
    else if (strcmp(argv[1], "JoinCluster") == 0) {
        if (argc < 3) {
            printf("\nUsage: %s JoinCluster <NFS Share path>\n", argv[0]);
        }
        else if (IsUserDomainAdmin()) {
            csm.JoinCluster(argv[2]);
        }
        else {
            printf("\nError, user is not a domain Admin!\n");
        }
    }
    else if (strcmp(argv[1], "UnjoinCluster") == 0) {
        if (IsUserDomainAdmin()) {
            csm.UnjoinCluster();
        }
        else {
            printf("\nError, user is not a domain Admin!\n");
        }
    }
    else if (strcmp(argv[1], "GenerateNewKey") == 0) {
        Buffer b;
        if (IsUserDomainAdmin() && doTlsServerPassword(b)) {
            WCHAR wcBuf[32];
            Buffer bNewKeyName;
            Buffer bKSP_w = scfg.GetValueW(KEY_STORAGE_PROVIDER);
            uint32_t numKeys = MyKeyManager::CountKeys();

            memset(wcBuf, 0, sizeof(wcBuf));
            swprintf_s(wcBuf, 32, L"-%u", numKeys);

            KSPkey ksp((WCHAR*)bKSP_w);
            bNewKeyName.Append((void*)MY_SERVER_KSP_KEY_NAME, wcslen((WCHAR*)MY_SERVER_KSP_KEY_NAME) * sizeof(WCHAR));
            bNewKeyName.Append((void*)wcBuf, wcslen((WCHAR*)wcBuf) * sizeof(WCHAR));
            bNewKeyName.NullTerminate_w();
            if (ERROR_SUCCESS == ksp.CreateKey((WCHAR*)bNewKeyName, NCRYPT_ALLOW_DECRYPT_FLAG)) {
                LocalClient lc;
                lc.SendToLocal(Commands::CMD_RELOAD_ROOT_KEYS, b);
            }
        }
    }
    else if (strcmp(argv[1], "ExportRootKeys") == 0) {
        Buffer b;
        if (argc != 3) {
            printf("usage: AuthService ExportRootKeys <FileName>\n");
        }
        else if (IsUserDomainAdmin() && doTlsServerPassword(b)) {
            uint32_t numKeys = 0;
            Buffer bOut;
            char pwd[MAX_PASSWD];
            char repeat[MAX_PASSWD];
            memset(pwd, 0, sizeof(pwd));
            memset(repeat, 0, sizeof(repeat));
            printf("\nEnter a STRONG password to securely encrypt the exported keys with: ");
            readPassword(pwd, sizeof(pwd));
            printf("\nConfirm the STRONG password: ");
            readPassword(repeat, sizeof(repeat));
            if (strcmp(pwd, repeat) == 0) {
                numKeys = MyKeyManager::ExportKeys(bOut, (uint8_t*)pwd, (uint32_t)strlen(pwd));
                if (1 == saveToFile((int8_t*)argv[2], (int8_t*)bOut, bOut.Size())) {
                    printf("\nSecurely exported %u keys to %s\n", numKeys, argv[2]);
                }
                else {
                    printf("\nFailed to save to %s!\n", argv[2]);
                }
            }
            else {
                printf("\nPasswords do not match!\n");
            }
            memset(pwd, 0, sizeof(pwd));
            memset(repeat, 0, sizeof(repeat));
        }
    }
#ifdef _DEBUG
    else if (strcmp(argv[1], "DebugService") == 0) {
        if (IsServiceAlreadyRunning()) {
            printf("\nService already running!\n");
            exit(-1);
        }
        else {
            CRLManager::Initialize();
            LocalServer   ls(ServiceType::SVC_TYPE_AUTH_SERVICE);
        }
    }
#endif
    else {
        printf("usage:  %s ---\n", argv[0]);
        return -1;
    }
    

    ApplicationStopped = TRUE;
    while (NumWorkersRunning > 0) {
        std::this_thread::yield();
    }

    mCLdap.Disconnect();

    WSACleanup();

    if (ghEventSource) {
        DeregisterEventSource(ghEventSource);
    }

    PasswordBuffer.Finalize();
    Buffer::Finishup();
    threadPool::Finalize();
    TLSServerContext::DeleteContext();

    return 0;
}
