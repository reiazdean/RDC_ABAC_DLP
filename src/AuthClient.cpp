/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include <WinSock2.h>
#include <windows.h>
#include <commdlg.h>
#include <Wincrypt.h>
#include "iphlpapi.h"
#include "strsafe.h"
#include <dsgetdc.h>
#include <Lm.h>
#include <conio.h>
#include <psapi.h>
#include <signal.h>
#include <msi.h>

#include "resource.h"
#include <Security.h>
#include <windowsx.h>
#include <Shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <sddl.h>

#include <commctrl.h>
#include <shlwapi.h>
#include <time.h>
#include <Dsgetdc.h>
#include <Lm.h>
#include <string>
#include <vector>

#include "OsslClientHelper.h"
#include "ECKeyPair.h"
#include "NdacConfig.h"
#include "x509class.h"
#include "DocHandler.h"
#include "threadPool.h"
#include "Widget.h"
#include "MyLdap.h"
#include "LocalClient.h"
#include "KSPkey.h"
#include "DilithiumKeyPair.h"
#include "KyberKeyPair.h"
#include "clusterClientManager.h"

using std::wstring;
using std::vector;

using namespace ReiazDean;

extern LRESULT  DoSCardDialog(HINSTANCE hinst, HWND hwndOwner, Buffer& bAttribs);
extern LRESULT  DoAddCertToSCardDialog(HINSTANCE hinst, HWND hwndOwner, Buffer& bUPN);
extern LRESULT  DoManagePrivateKeysDialog(HINSTANCE hinst, HWND hwndOwner, Buffer& bChosen);
extern LRESULT  DoConfigDialog(HINSTANCE hinst, HWND hwndOwner);
extern void Message(LPWSTR szPrefix, HRESULT hr);
extern void* MonitorFirewall(void* args);
extern int FirewallBlockAllButThisIP(Buffer& ipAdr);
int ShowLocalFiles();
int Connect();

std::atomic<int> NumWorkersRunning = 0;
std::atomic<SOCKET> SandboxSocket = 0;

#define MAX_LOADSTRING 100

#define LEFT_INSET				100
#define TOP_INSET				10
#define RIGHT_INSET             25
#define INFO_BUFFER_SIZE		2048
#define	MAX_UNLICNESED_USERS	16

#define BORDER_SZ               1
#define NUM_RESOURCE_ICONS      1
#define MIN_SUCCESS             (HINSTANCE)32
#define STRING_SZ               128
#define INFO_STRING_SZ          1024

#define MAX_SMALL_ICONS         1024
#define CLASSIFIED_ICON         109
#define START_ICON              299
#define INSTALLER_ICON          130
#define UNKNOWN_ICON            23
#define PB_MAX                  65535

#define NUM_TOOLBAR_BUTTONS     6

#define NUM_PLACEMENTS 16
#define BUTTON_HEIGHT 90
#define BUTTON_WIDTH 5

typedef struct {
    Widget* widget;
    int widthPercent;
    int heightPercent;
} WidgetPlacements;

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK		EnumChildProc(HWND hwndChild, LPARAM lParam);
BOOL				InitTreeViewImageLists(HINSTANCE hInstance);

LPTSTR CommandLine = nullptr;
std::atomic<BOOL> UIready = FALSE;
std::atomic<BOOL> ApplicationStopped = FALSE;
std::mutex MyMutex;

int SandBoxedState = NdacClientConfig::SandboxedState::OUTSIDE;
DWORD SandBoxProcess = 0;
LocalClient* MyLocalClient = nullptr;

//All the static and global buffers here for orderly creation and destruction
//***************************************************************************
MemoryPoolManager  Buffer::MyMemPoolManager;
CLdap CLdap::TheCLdap;//the constructor creates Buffers
NdacClientConfig NdacClientConfig::TheNdacClientConfig;
ClusterClientManager ClusterClientManager::TheClusterClientManager;
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
DilithiumKeyPair TLSContext::s_DilithiumKeyPair;
Buffer UserPrincipalName;//for addCertToSCardDlg
Buffer MyChosenKey;
Buffer SandBoxAuthBuf;
Buffer GatewayIP;
Buffer CmdTree;
Buffer SelectedRemoteFolder;
Buffer SelectedRemoteFile;
Buffer SelectedLocalFolder;
Buffer SelectedLocalFile;
Buffer* pPasswordBuffer = nullptr;
//***************************************************************************

// Global Variables:
HCURSOR hWaitCursor = NULL;
HCURSOR hOldCursor = NULL;
COLORREF colorRed = RGB(255, 0, 0);
COLORREF colorGreen = RGB(0, 255, 0);
COLORREF colorBlue = RGB(0, 0, 255);
HFONT hAppFont = NULL;
HFONT hSmallFont = NULL;
HBRUSH hWindowBrush = NULL;
HBRUSH hButtonBrush = NULL;
HBRUSH h3DlightBrush = NULL;
HWND hAppWnd = NULL;
HTREEITEM Selected = NULL;
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name
time_t  appStart;
unsigned long long mouseMoves = 0;

std::atomic<bool> OperationInProgress = false;

Widget MainWinWidget;
Widget ToolBarWidget;
Widget ProgressBarWidget;
Widget ProgressTextWidget;
Widget ButtonWidget[NUM_TOOLBAR_BUTTONS];
Widget AppsViewWidget;
Widget RemoteDirTitleWidget;
Widget RemoteFilesTitleWidget;
Widget LocalDirTitleWidget;
Widget LocalFilesTitleWidget;
Widget RemoteTreeWidget;
Widget RemoteFilesWidget;
Widget LocalTreeWidget;
Widget LocalFilesWidget;
Widget RemoteStatusWidget;
Widget LocalStatusWidget;
Widget UserPrincipalWidget;
WidgetPlacements* pWidgetPlacements = nullptr;

int hwndIconIndices[NUM_TOOLBAR_BUTTONS] = {
    238,
    194,
    207,
    104,
    111,
    90
};

HIMAGELIST hFolderImgList = 0;
HIMAGELIST hShellImages = 0;  // handle to image list
HIMAGELIST hAppImages = 0;
HIMAGELIST hInstalledAppsImgList = 0;
HICON hAppIcon = 0;

HICON hSmallIcons[MAX_SMALL_ICONS];
UINT numIcons = 0;
UINT numUsers = 0;

HWND hwndTT = NULL;

map< std::wstring, std::wstring >         PrivateMaps;

WCHAR wcEnglishTooltips[NUM_TOOLBAR_BUTTONS][STRING_SZ] = {
L"Load or reload all classified documents.",
L"Create smartcard CSR.",
L"Add certificate to the smartcard.",
L"Smartcard private keys.",
L"About me.",
L"Configuration",
};

WCHAR wcCommandStrings[CMD_NULL + 1][STRING_SZ] = {
    L"CMD_GET_SERVER_NONCE",
    L"CMD_GET_CLIENT_SANDBOX_STATE",
    L"CMD_GET_CLIENT_SANDBOX_SCRIPT",
    L"CMD_EXCHANGE_ECDH_KEYS",
    L"CMD_EXCHANGE_KYBER_KEYS",
    L"CMD_SEND_NODE_SECRET",
    L"CMD_SEND_TLS_PK_PASSWD",
    L"CMD_EXCHANGE_HSM_PASSWD",
    L"CMD_EXCHANGE_CLUSTER_MBRS",
    L"CMD_CLUSTER_ADD_MBR",
    L"CMD_CLUSTER_REMOVE_MBR",
    L"CMD_CLUSTER_REGISTER_CLIENT",
    L"CMD_GET_MLS_MCS_AES_ENC_KEY",
    L"CMD_GET_MLS_MCS_AES_DEC_KEY",
    L"CMD_UPLOAD_DOCUMENT",
    L"CMD_DOWNLOAD_DOCUMENT",
    L"CMD_PUBLISH_DOCUMENT",
    L"CMD_DECLASSIFY_DOCUMENT",
    L"CMD_UPLOAD_CERT_REQUEST",
    L"CMD_DOWNLOAD_CERTIFICATE",
    L"CMD_DOWNLOAD_SW_INSTALLER",
    L"CMD_DOWNLOAD_DECLASSIFIED",
    L"CMD_VERIFY_DOCUMENT",
    L"CMD_GET_DOCUMENT_TREE",
    L"CMD_GET_DOCUMENT_NAMES",
    L"CMD_RELOAD_REGISTERED_CLIENTS",
    L"CMD_RELOAD_ROOT_KEYS",
    L"CMD_STOP_LOCAL_SERVICE",
    L"CMD_OOB_AUTHENTICATE",
    L"CMD_OOB_GET_ICON_DIR",
    L"CMD_OOB_GET_SC_CERT",
    L"CMD_OOB_SC_SIGN",
    L"CMD_OOB_SC_SIGN_DOC_HASH",
    L"CMD_TIMESTAMP_SIGN",
    L"CMD_NULL"
};

WCHAR wcErrorStrings[RSP_NULL + 1][STRING_SZ] = {
L"RSP_SUCCESS",
L"RSP_NOT_AUTHORIZED",
L"RSP_USER_MCS_UNAUTHORIZED",
L"RSP_USER_MLS_UNAUTHORIZED",
L"RSP_HOST_MLS_UNAUTHORIZED",
L"RSP_NOT_VALID_NODE",
L"RSP_INVALID_COMMAND",
L"RSP_KEY_GEN_ERROR",
L"RSP_MEMORY_ERROR",
L"RSP_DIGEST_ERROR",
L"RSP_CIPHER_ERROR",
L"RSP_FILE_ERROR",
L"RSP_SOCKET_IO_ERROR",
L"RSP_INTERNAL_ERROR",
L"RSP_SIGNATURE_INVALID",
L"RSP_HASH_MISMATCH",
L"RSP_FILE_MOVE_ERROR",
L"RSP_CERT_REVOKED",
L"RSP_CERT_INVALID",
L"RSP_NO_ITEMS_FOUND",
L"RSP_CANNOT_LOCK_FILE",
L"RSP_COMMAND_TIMEOUT",
L"RSP_MAX_PATH_EXCEEDED",
L"RSP_NULL"
};

WCHAR  WC_STATUS[] = L"Status Output";

WidgetPlacements* GetPlacementFor(Widget* pWidget) {
    for (int i = 0; i < NUM_PLACEMENTS; i++) {
        if (pWidgetPlacements[i].widget == pWidget) {
            return &pWidgetPlacements[i];
        }
    }

    return nullptr;
}

bool UpProgress()
{
    if (!OperationInProgress) {
        if (hWaitCursor) {
            hOldCursor = SetCursor(hWaitCursor);
        }
        OperationInProgress = true;
        return true;
    }
    return false;
}

void DownProgress()
{
    if (hOldCursor) {
        SetCursor(hOldCursor);
    }
    OperationInProgress = false;
}

bool IsAdmin()
{
#ifdef _DEBUG
    return false;
#else
    return (IsUserLocalAdmin() || IsUserDomainAdmin());
#endif
}

bool IsNotAdmin()
{
    return !IsAdmin();
}

WCHAR* ClientChooseUserKey()
{
    try {
        std::unique_lock<std::mutex> mlock(MyMutex);
        if (MyChosenKey.Size() > 0) {
            return (WCHAR*)MyChosenKey;
        }
        else {
            Buffer bCert;
            DoManagePrivateKeysDialog(hInst, hAppWnd, MyChosenKey);
            if (!KSPGetUserCertificate((WCHAR*)MyChosenKey, bCert)) {
                MessageBox(hAppWnd, L"Your chosen Smartcard key set does not contain a certificate!\nTry again!", L"Error", MB_OK);
                MyChosenKey.Clear();
                return nullptr;
            }
            return (WCHAR*)MyChosenKey;
        }
    }
    catch (...) {
        MessageBox(hAppWnd, L"You did not choose a Smartcard key set!\nTry again!", L"Error", MB_OK);
        return nullptr;
    }
}

void SetStatus(HWND hWnd, WCHAR* pwcText, bool bAppend)
{
    try {
        Buffer bMsg;
        WCHAR cDate[64] = { 0 };
        WCHAR cTime[64] = { 0 };

        if (!hWnd || !pwcText) {
            return;
        }

        GetDateFormat(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, NULL, NULL, cDate, 64);
        GetTimeFormat(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, NULL, NULL, cTime, 64);
        bMsg.Append((void*)cDate, wcslen(cDate) * sizeof(WCHAR));
        bMsg.Append((void*)L" ", sizeof(WCHAR));
        bMsg.Append((void*)cTime, wcslen(cTime) * sizeof(WCHAR));
        bMsg.Append((void*)L"\r\n", sizeof(WCHAR) * 2);

       // std::unique_lock<std::mutex> mlock(MyMutex);
        if (bAppend) {
            int sz = GetWindowTextLength(hWnd);
            if (sz) {
                Buffer b;
                Buffer tmp(sz * sizeof(WCHAR));
                WCHAR wcSep[] = L"\r\n===========================================================================\r\n";
                b.Append((void*)pwcText, wcslen(pwcText) * sizeof(WCHAR));
                b.Append((void*)wcSep, wcslen(wcSep) * sizeof(WCHAR));
                GetWindowText(hWnd, (WCHAR*)tmp, sz);
                b.Append((void*)tmp, sz * sizeof(WCHAR));
                bMsg.Append(b);
            }
        }
        else {
            bMsg.Append((void*)pwcText, wcslen(pwcText) * sizeof(WCHAR));
        }

        SetWindowText(hWnd, (WCHAR*)bMsg);
    }
    catch (...) {
        return;
    }
}

void SetLocalStatus(WCHAR* pwcText, bool bAppend)
{
    if (UIready && pwcText) {
        SetStatus(LocalStatusWidget.GetHWnd(), pwcText, bAppend);
    }
}

void SetRemoteStatus(WCHAR* pwcText, bool bAppend)
{
    if (UIready && pwcText) {
        SetStatus(LocalStatusWidget.GetHWnd(), pwcText, bAppend);
    }
}

void SetCommandStatus(ReiazDean::Commands cmd, ReiazDean::Responses resp)
{
    if (UIready) {
        WCHAR wcBuf[MAX_LINE];
        memset(wcBuf, 0, sizeof(wcBuf));
        swprintf_s(wcBuf, MAX_LINE - 1, L"Command: %s Result: %s\n", wcCommandStrings[cmd], wcErrorStrings[resp]);
        SetStatus(RemoteStatusWidget.GetHWnd(), wcBuf, true); //SetRemoteStatus(wcBuf, true);
    }
}

bool GetLocalClassifiedFolder(Buffer& bFolder)
{
    try {
        size_t requiredSize = 0;

        _wgetenv_s(&requiredSize, 0, 0, L"APPDATA");
        if (requiredSize > 0)
        {
            size_t sz = 0;
            Buffer bEnv(requiredSize * sizeof(wchar_t));
            _wgetenv_s(&requiredSize, (wchar_t*)bEnv, requiredSize, L"APPDATA");
            bFolder.Clear();
            bFolder.Append((void*)bEnv, requiredSize * sizeof(wchar_t) - sizeof(wchar_t));
            bFolder.Append((void*)L"\\classified", wcslen(L"\\classified") * sizeof(WCHAR));
            return true;
        }
    }
    catch (...) {
        bFolder.Clear();
        return false;
    }

    return false;
}

bool IsFileLocal(Buffer& bCmd, Buffer& bLocalName, int32_t& sz) {
    try {
        struct _stat sbuf;
        Buffer bFolder;
        wchar_t fname[MAX_NAME];
        if (bCmd.Size() >= (sizeof(CommandHeader) + sizeof(AuthorizationRequest))) {
            uint8_t* pChar = (uint8_t*)bCmd + sizeof(CommandHeader);
            AuthorizationRequest* pAR = (AuthorizationRequest*)pChar;
            size_t count = 0;
            std::vector<WCHAR*> out;

            memcpy(fname, pAR->docMAC.mls_doc_name, MAX_NAME);
            count = splitStringW((WCHAR*)fname, (WCHAR*)L"\\", out);
            GetLocalClassifiedFolder(bFolder);
            bFolder.Append((void*)L"\\SoftwareInstallers\\", wcslen(L"\\SoftwareInstallers\\") * sizeof(WCHAR));
            if (count > 0) {
                bFolder.Append((void*)out.at(count - 1), wcslen((WCHAR*)out.at(count - 1)) * sizeof(WCHAR));
            }
            bFolder.NullTerminate_w();
            bLocalName = bFolder;
            _wstat((wchar_t*)bFolder, &sbuf);
            if (sbuf.st_size > 0) {
                sz = sbuf.st_size;
                return true;
            }
        }
    }
    catch (...) {
        bLocalName.Clear();
        sz = 0;
        return false;
    }

    return false;
}

void* OpenSelectedProc(void* args)
{
    try {
        SHELLEXECUTEINFO ShExecInfo;
        Buffer bSelected(SelectedLocalFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedLocalFile);

        ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
        ShExecInfo.fMask = NULL;
        ShExecInfo.hwnd = NULL;
        ShExecInfo.lpVerb = NULL;
        ShExecInfo.lpFile = (WCHAR*)bSelected;
        ShExecInfo.lpParameters = NULL;
        ShExecInfo.lpDirectory = NULL;
        ShExecInfo.nShow = SW_MAXIMIZE;
        ShExecInfo.hInstApp = NULL;
        ShellExecuteEx(&ShExecInfo);
    }
    catch (...) {
        return 0;
    }

    return 0;
}

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
bool IsWindowsSandbox(DWORD processID)
{
    bool bRc = false;
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    // Get the process name.
    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
            if (wcsncmp(L"WindowsSandbox", szProcessName, 14) == 0) {
                bRc = true;
            }
        }
        CloseHandle(hProcess);
    }

    return bRc;
}

bool IsWinSandboxRunning(void)
{
    // Get the list of process identifiers.
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return true;
    }

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);
    // Print the name and process identifier for each process.
    SandBoxProcess = 0;
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            if (IsWindowsSandbox(aProcesses[i])) {
                SandBoxProcess = aProcesses[i];
                return true;
            }
        }
    }

    return false;
}

//std::mutex tmpMutex;
Responses RequestAuthorizationA(
    TLSClientContext& client,
    Buffer& bCmd,
    Buffer& bResp,
    bool closeClient = true)
{
    try {
        ResponseHeader* prh = nullptr;
        condition_variable cv;
        ClusterClientManager& ccm = ClusterClientManager::GetInstance();
        Buffer mbr;
        if (ccm.RoundRobin(mbr) && (mbr.Size() > 0)) {
            if (OsslClientHelper::QueueCommand(client, bCmd, mbr, bResp, cv)) {
                std::unique_lock<std::mutex> mlock(MyMutex);
                //cv.wait_for(mlock, std::chrono::seconds(10));
                cv.wait(mlock);
                if (bResp.Size() >= sizeof(ResponseHeader)) {
                    prh = (ResponseHeader*)bResp;
                    {
                        CommandHeader* pch = (CommandHeader*)bCmd;
                        SetCommandStatus(pch->command, prh->response);
                    }
                    return prh->response;
                }
            }
        }

        return RSP_INTERNAL_ERROR;
    }
    catch (...) {
        return RSP_INTERNAL_ERROR;
    }
}

bool ProxyRequestAuthorization(
    Buffer& bCmd,
    Buffer& resp
)
{
    return (MyLocalClient->SendToProxy(bCmd, resp) == RSP_SUCCESS);
}

bool RequestAuthorization(
    TLSClientContext& client,
    const AuthorizationRequest* preq,
    Commands cmdCode,
    Buffer& resp,
    bool closeClient = true) {
    try {
        CommandHeader ch;
        Buffer bCmd;

        ch.command = cmdCode;
        ch.szData = 0;
        if (preq) {
            ch.szData = sizeof(AuthorizationRequest);
            bCmd.Append((void*)&ch, sizeof(ch));
            bCmd.Append((void*)preq, sizeof(AuthorizationRequest));
        }
        else {
            bCmd.Append((void*)&ch, sizeof(ch));
        }

        if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
            return ProxyRequestAuthorization(bCmd, resp);
        }

        return (RequestAuthorizationA(client, bCmd, resp, closeClient) == RSP_SUCCESS);
    }
    catch (...) {
        resp.Clear();
        return false;
    }
}

int TerminateSandbox()
{
    // Replace with the process ID of the process you want to terminate
    DWORD processID = SandBoxProcess;

    // Open the process with PROCESS_TERMINATE access
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL)
    {
        return 1;
    }

    // Terminate the process
    if (!TerminateProcess(hProcess, 1))
    {
        CloseHandle(hProcess);
        return 1;
    }

    // Close the process handle
    CloseHandle(hProcess);

    return 0;
}

Responses
RequestResponse(
    Buffer& bCmd,
    Buffer& bResp,
    ECKeyPair& myECKeyPair,
    TLSClientContext& client)
{
    try {
        Responses response = RSP_SUCCESS;
        CommandHeader* pch = nullptr;

        bResp.Clear();
        pch = (CommandHeader*)bCmd;
        switch (pch->command) {
        case Commands::CMD_EXCHANGE_ECDH_KEYS:
        {
            uint8_t* pcOSpubKey = nullptr;
            uint32_t szOSpub = 0;
            pcOSpubKey = myECKeyPair.GetPublicKey();
            szOSpub = myECKeyPair.GetPublicKeySize();
            myECKeyPair.DeriveAESkey((uint8_t*)bCmd + sizeof(CommandHeader), pch->szData);
            bResp.Append(pcOSpubKey, szOSpub);
            break;
        }
        case Commands::CMD_OOB_AUTHENTICATE:
        {
            ResponseHeader respH = { RSP_NOT_AUTHORIZED, 0 };
            uint8_t nonce[16];
            Buffer bTmp((uint8_t*)bCmd + sizeof(CommandHeader), pch->szData);
            if (bTmp.Equals((void*)SandBoxAuthBuf, SandBoxAuthBuf.Size())) {
                respH.response = RSP_SUCCESS;
            }
            SandBoxAuthBuf.Clear();
            RAND_bytes(nonce, sizeof(nonce));
            hexEncode(nonce, sizeof(nonce), SandBoxAuthBuf);
            SandBoxAuthBuf.NullTerminate();

            bResp.Append((void*)&respH, sizeof(respH));
            break;
        }
        case Commands::CMD_OOB_GET_ICON_DIR:
        {
            Buffer bIcons;
            NdacClientConfig& ccfg = NdacClientConfig::GetInstance();
            ccfg.GetValue(SANDBOX_ICONS, bIcons);
            bIcons.NullTerminate();
            bResp.Append(bIcons);
            break;
        }
        case Commands::CMD_OOB_GET_SC_CERT:
        {
            KSPGetUserCertificate(ChooseUserKey(), bResp);
            break;
        }
        case Commands::CMD_OOB_SC_SIGN_DOC_HASH:
        {
            SequenceReaderX seq;
            Buffer bTmp((uint8_t*)bCmd + sizeof(CommandHeader), pch->szData);
            if (seq.Initilaize(bTmp)) {
                Buffer bHash;
                Buffer bDocSz;
                if (seq.getValueAt(0, bHash) && seq.getValueAt(1, bDocSz)) {
                    uint32_t encryptedSz;
                    memcpy(&encryptedSz, (void*)bDocSz, sizeof(uint32_t));
                    KSPwrapClientCertAndSigForDoc(ChooseUserKey(), (uint8_t*)bHash, bHash.Size(), encryptedSz, bResp);
                }
            }
            break;
        }
        case Commands::CMD_DOWNLOAD_SW_INSTALLER:
        {
            Buffer bLocalName;
            int32_t szDoc = 0;
            if (IsFileLocal(bCmd, bLocalName, szDoc)) {
                ResponseHeader respH = { RSP_SUCCESS, 0 };
                respH.szData = szDoc;
                bResp.Clear();
                bResp.Append((void*)&respH, sizeof(ResponseHeader));
                return RSP_SUCCESS;
            }
            else {
                response = RequestAuthorizationA(client, bCmd, bResp, false);
            }
            break;
        }
        case Commands::CMD_DOWNLOAD_DOCUMENT:
        case Commands::CMD_UPLOAD_DOCUMENT:
        {
            response = RequestAuthorizationA(client, bCmd, bResp, false);
            break;
        }
        default:
            response = RequestAuthorizationA(client, bCmd, bResp, true);
            break;
        }

        return response;
    }
    catch (...) {
        bResp.Clear();
        return RSP_INTERNAL_ERROR;
    }
}

void*
OutOfBoxServer(void* args)
{
    int ret;
    int result;
    ECKeyPair myECKeyPair;

    SandboxSocket = OpenServerInetSocket(1991);
    if (SandboxSocket == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ret = listen(SandboxSocket, 1);
    if (ret == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    NumWorkersRunning++;
    /* This is the main loop for handling connections. */
    while (!ApplicationStopped) {
        SOCKET data_socket;
        int r;
        r = Select(SandboxSocket, 0, 500000, true);
        if (r == 0) {
            continue;
        }
        else if (r < 0) {//sandbox ended
            break;
        }

        /* Wait for incoming connection. */
        data_socket = accept(SandboxSocket, NULL, NULL);
        if (data_socket == -1) {
            continue;
        }

        result = 0;
        SetToNotBlock(data_socket);

        while (!ApplicationStopped) {
            TLSClientContext client;
            Buffer         bCmd;
            Buffer         bResp;
            ResponseHeader rh;
            
            r = Select(data_socket, 0, 500000, true);
            if (r == 0) {
                if (IsWinSandboxRunning()) {
                    continue;
                }
                else {
                    break;
                }
            }
            else if (r < 0) {
                if (IsWinSandboxRunning()) {
                    TerminateSandbox();
                }
                break;
            }

            result = NonBlockingRead(data_socket, bCmd);
            if (result <= 0) {
                if (IsWinSandboxRunning()) {
                    TerminateSandbox();
                }
                break;
            }

            if (result < sizeof(CommandHeader)) {
                if (IsWinSandboxRunning()) {
                    TerminateSandbox();
                }
                break;
            }

            {
                Buffer b;
                rh.response = RequestResponse(bCmd, bResp, myECKeyPair, client);
                rh.szData = bResp.Size();
                b.Append((void*)&rh, sizeof(ResponseHeader));
                b.Append(bResp);
                result = NonBlockingWrite(data_socket, b);
            }
            if (result >= 0) {
                if (rh.response == RSP_SUCCESS) {
                    CommandHeader* pch = nullptr;
                    pch = (CommandHeader*)bCmd;
                    ResponseHeader* prh = nullptr;
                    prh = (ResponseHeader*)bResp;
                    switch (pch->command) {
                    case Commands::CMD_DOWNLOAD_SW_INSTALLER:
                    {
                        Buffer bLocalName;
                        int32_t szDoc = 0;
                        if (IsFileLocal(bCmd, bLocalName, szDoc)) {
                            DocHandler::ProxySendLocalDocument(data_socket, bLocalName);
                        }
                        else {
                            int32_t len = prh->szData;
                            DocHandler::ProxyReceiveDocument(client, data_socket, len, bLocalName);
                        }
                        break;
                    }
                    case Commands::CMD_DOWNLOAD_DOCUMENT:
                    {
                        int32_t len = prh->szData;
                        DocHandler::ProxyReceiveDocument(client, data_socket, len, nullptr);
                        break;
                    }
                    case Commands::CMD_UPLOAD_DOCUMENT:
                    {
                        uint8_t* pChar = (uint8_t*)bCmd + sizeof(CommandHeader);
                        AuthorizationRequest* pAR = (AuthorizationRequest*)pChar;
                        DocHandler::ProxyReceiveSendDocument(client, data_socket, pAR->docMAC.mls_doc_size);
                        break;
                    }
                    default:
                        break;
                    }
                }
            }

        }
        {
            WCHAR msg[64];
            swprintf_s(msg, 64, L"data socket %u closed\n", (uint32_t)data_socket);
            SetLocalStatus(msg, false);
        }
        CloseSocket(data_socket);
        break;
    }
    NumWorkersRunning--;

    CloseSocket(SandboxSocket);
    SandboxSocket = 0;

    return 0;
}

void Map(std::wstring key, std::wstring value)
{
    std::unique_lock<std::mutex> mlock(MyMutex);
    PrivateMaps[key] = value;
}

std::wstring GetMappedValue(std::wstring aKey)
{
    std::unique_lock<std::mutex> mlock(MyMutex);
    for (auto it = PrivateMaps.begin(); it != PrivateMaps.end(); ++it)
    {
        std::wstring key = it->first;
        std::wstring value = it->second;
        if (key.compare(aKey) == 0)
        {
            return value;
        }
    }

    return L"";
}

bool GetWorkingDirectory(Buffer& bDocsFolder)
{
    try {
        size_t requiredSize = 0;
        _wgetenv_s(&requiredSize, 0, 0, L"APPDATA");
        if (requiredSize > 0)
        {
            WCHAR wcDir[] = L"\\classified\\Temp";
            Buffer bEnv(requiredSize * sizeof(WCHAR) + sizeof(WCHAR));

            _wgetenv_s(&requiredSize, (WCHAR*)bEnv, requiredSize, L"APPDATA");
            bDocsFolder.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
            bDocsFolder.Append((void*)wcDir, wcslen(wcDir) * sizeof(WCHAR));
            bDocsFolder.NullTerminate_w();
            return true;
        }
    }
    catch (...) {
        bDocsFolder.Clear();
        return false;
    }

    return false;
}

bool CreateClassifiedRootFolders()
{
    try {
        size_t requiredSize = 0;
        _wgetenv_s(&requiredSize, 0, 0, L"APPDATA");
        if (requiredSize > 0)
        {
            Buffer bPerm, bTemp, bSI;
            Buffer bEnv(requiredSize * sizeof(WCHAR) + sizeof(WCHAR));
            _wgetenv_s(&requiredSize, (WCHAR*)bEnv, requiredSize, L"APPDATA");
            bPerm.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
            bPerm.Append((void*)L"\\classified", wcslen(L"\\classified") * sizeof(WCHAR));
            bTemp = bPerm;
            bSI = bPerm;

            bPerm.NullTerminate_w();
            if (!CreateDirectory((WCHAR*)bPerm, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }

            bTemp.Append((void*)L"\\Temp", wcslen(L"\\Temp") * sizeof(WCHAR));
            bTemp.NullTerminate_w();
            if (!CreateDirectory((WCHAR*)bTemp, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }

            bSI.Append((void*)L"\\SoftwareInstallers", wcslen(L"\\SoftwareInstallers") * sizeof(WCHAR));
            bSI.NullTerminate_w();
            if (!CreateDirectory((WCHAR*)bSI, 0)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }

            return true;
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

bool SaveCSR(Buffer& bCSR, char* pcName)
{
    try {
        if (pcName) {
            TLSClientContext client;
            Buffer resp;
            Buffer upn;
            ResponseHeader* prh;
            //
            CommandHeader ch;
            Buffer bCmd;

            upn.Append((void*)pcName, strlen(pcName));
            upn.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bCSR.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bCSR.Prepend(upn);
            bCSR.ASN1Wrap(CONSTRUCTED_SEQUENCE);

            ch.command = CMD_UPLOAD_CERT_REQUEST;
            ch.szData = bCSR.Size();
            bCmd.Append((void*)&ch, sizeof(ch));
            bCmd.Append((void*)bCSR, bCSR.Size());

            if (RequestAuthorizationA(client, bCmd, resp, true) == RSP_SUCCESS) {
                prh = (ResponseHeader*)resp;
                if (prh) {
                    WCHAR wcBuf[MAX_LINE];
                    memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
                    swprintf_s(wcBuf, MAX_LINE, L"CSR saving Response = %s(%d)\r\n", wcErrorStrings[prh->response], prh->response);
                    SetLocalStatus((WCHAR*)wcBuf, true);
                    return (prh->response == RSP_SUCCESS);
                }
            }
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

bool DownloadCertificate(Buffer& bUPN, Buffer& bCert)
{
    bool bRc = false;
    try {
        TLSClientContext client;
        Buffer resp;
        ResponseHeader* prh;
        CommandHeader ch;
        Buffer bCmd;

        ch.command = CMD_DOWNLOAD_CERTIFICATE;
        ch.szData = bUPN.Size();
        bCmd.Append((void*)&ch, sizeof(ch));
        bCmd.Append((void*)bUPN, bUPN.Size());

        if (RequestAuthorizationA(client, bCmd, resp, true) == RSP_SUCCESS) {
            prh = (ResponseHeader*)resp;
            if (prh->response == RSP_SUCCESS) {
                uint8_t* pChar = (uint8_t*)resp + sizeof(ResponseHeader);
                int32_t len = prh->szData;
                bCert.Clear();
                bCert.Append((void*)pChar, len);
                bRc = true;
            }
        }
    }
    catch (...) {
        bCert.Clear();
        return false;
    }

    return bRc;
}

bool GetSandboxScript(Buffer& bScript)
{
    bool bRc = false;
    try {
        TLSClientContext client;
        Buffer resp;
        ResponseHeader* prh;
        CommandHeader ch;
        Buffer bCmd;

        ch.command = CMD_GET_CLIENT_SANDBOX_SCRIPT;
        ch.szData = 0;
        bCmd.Append((void*)&ch, sizeof(ch));

        if (RequestAuthorizationA(client, bCmd, resp, true) == RSP_SUCCESS) {
            prh = (ResponseHeader*)resp;
            if (prh->response == RSP_SUCCESS) {
                uint8_t* pChar = (uint8_t*)resp + sizeof(ResponseHeader);
                int32_t len = prh->szData;
                bScript.Clear();
                bScript.Append((void*)pChar, len);
                bRc = true;
            }
        }
    }
    catch (...) {
        bScript.Clear();
        return false;
    }

    return bRc;
}

bool ChooseCertFile(Buffer& bFname) {
    try {
        OPENFILENAMEA ofn; // Initialize the structure
        char szFile[MAX_PATH] = ""; // Buffer to store the selected file path

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = NULL;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        //ofn.lpstrFilter = "All Files\0*.*\0"; // Filter for file types
        ofn.lpstrFilter = "*.cer\0"; // Filter for file types
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameA(&ofn)) // Display the dialog
        {
            bFname.Append((void*)szFile, strlen(szFile));
            bFname.NullTerminate();
            return true;
        }
    }
    catch (...) {
        bFname.Clear();
        return false;
    }

    return false;
}

void Launch(WCHAR* pwcApp)
{
    try {
        Buffer workDir;
        const WCHAR* cmd = L""; // Command line arguments (if any)

        STARTUPINFO info = { sizeof(info) };
        PROCESS_INFORMATION processInfo;

        if (GetWorkingDirectory(workDir) && SetCurrentDirectory((WCHAR*)workDir)) {
            if (CreateProcess(pwcApp, (LPWSTR)cmd, nullptr, nullptr, TRUE, 0, nullptr, (WCHAR*)workDir, &info, &processInfo)) {
                WaitForSingleObject(processInfo.hProcess, INFINITE);
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);
            }
        }
    }
    catch (...) {
        return;
    }

    return;
}

void CreateToolTip()
{
    LRESULT res;
    BOOL bRes;

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_WIN95_CLASSES;
    bRes = InitCommonControlsEx(&icc);

    // Create a tooltip.
    hwndTT = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL,
        WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        hAppWnd, NULL, hInst, NULL);

    res = SendMessage(hwndTT, TTM_ACTIVATE, TRUE, 0);
}

void RegisterToolWithTooltip(HWND hwndParent, WCHAR* pwcText)
{
    LRESULT res;
    TOOLINFOW ti = { 0 };
    ti.cbSize = TTTOOLINFO_V1_SIZE;//sizeof(TOOLINFOW);
    ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
    ti.hwnd = hwndParent;
    ti.uId = (UINT_PTR)hwndParent;
    ti.hinst = hInst;
    ti.lpszText = pwcText;

    GetWindowRect(hwndParent, &ti.rect);

    // Associate the tooltip with the "tool" window.
    res = SendMessage(hwndTT, TTM_ADDTOOLW, 0, (LPARAM)(LPTOOLINFOW)&ti);
}

void ReRegisterToolWithTooltip(HWND hwndParent, WCHAR* pwcText)
{
    LRESULT res;
    TOOLINFOW ti = { 0 };
    ti.cbSize = TTTOOLINFO_V1_SIZE;//sizeof(TOOLINFOW);
    ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
    ti.hwnd = hwndParent;
    ti.uId = (UINT_PTR)hwndParent;
    ti.hinst = hInst;
    ti.lpszText = pwcText;

    GetWindowRect(hwndParent, &ti.rect);

    // Associate the tooltip with the "tool" window.
    res = SendMessage(hwndTT, TTM_UPDATETIPTEXT, 0, (LPARAM)(LPTOOLINFOW)&ti);
}
/*
* This seems harsh but we want to shutdown the Sandbox in the event the user tries to defeat isolation by messing with the firewall rules.
* Only revelant when the client is inside the sandbox
*/
BOOL MySystemShutdown()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // Get a token for this process. 

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return(FALSE);

    // Get the LUID for the shutdown privilege. 

    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
        &tkp.Privileges[0].Luid);

    tkp.PrivilegeCount = 1;  // one privilege to set    
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Get the shutdown privilege for this process. 

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
        (PTOKEN_PRIVILEGES)NULL, 0);

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    // Shut down the system and force all applications to close. 
    InitiateSystemShutdownExA(NULL, NULL, 0, TRUE, FALSE, SHTDN_REASON_MAJOR_APPLICATION);
    /*if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
        SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
        SHTDN_REASON_MINOR_UPGRADE |
        SHTDN_REASON_FLAG_PLANNED))
        return FALSE;*/

    //shutdown was successful
    return TRUE;
}

typedef void (*SignalHandlerPointer)(int);

void SignalHandler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
            MySystemShutdown();
        }
        break;
    default:
        break;
    }
}

bool IsSandboxedClient()
{
    bool bRc = true;
    ClusterClientManager& ccm = ClusterClientManager::GetInstance();

    EnableWindow(ButtonWidget[0].GetHWnd(), FALSE);
    UpProgress();

    bRc = ccm.IsSandboxedClient();

    DownProgress();
    
    EnableWindow(ButtonWidget[0].GetHWnd(), !IsAdmin());

    return bRc;
}

void* StartupChecks(void* args) {
    try {
        NdacClientConfig& ccfg = NdacClientConfig::GetInstance();

        DilithiumKeyPair& dpk = TLSContext::GetDilithium();
        Buffer bPKfile = ccfg.GetValue(DILITHIUM_PUBLIC_FILE);
        if (!dpk.ReadPublic((char*)bPKfile)) {
            MessageBoxA(NULL, "No Dilithium public key found!", "Error", MB_OK);
            //exit(-1);
        }
        SandBoxedState = IsSandboxedClient() ? NdacClientConfig::SandboxedState::OUTSIDE : NdacClientConfig::SandboxedState::NONE;
        threadPool::queueThread((void*)ClusterClientManager::ClusterClientRecoveryProc, (void*)NULL);
    }
    catch (...) {
        return 0;
    }
    return 0;
}

int WINAPI wWinMain(
        _In_      HINSTANCE hInstance,
        _In_opt_  HINSTANCE hPrevInstance,
        _In_      PWSTR     pCmdLine,
        _In_      int       nCmdShow)
{
    WidgetPlacements placements[NUM_PLACEMENTS] = {
        {&MainWinWidget, 100, 100},
        {&ToolBarWidget, 100, 5},
        {&UserPrincipalWidget, 25, 50},
        {&ProgressBarWidget, 20, 50},
        {&ProgressTextWidget, 20, 50},
        {&AppsViewWidget, 100, 2},
        {&RemoteDirTitleWidget, 20, 2},
        {&RemoteFilesTitleWidget, 30, 2},
        {&LocalDirTitleWidget, 20, 2},
        {&LocalFilesTitleWidget, 30, 2},
        {&RemoteTreeWidget, 20, 60},
        {&RemoteFilesWidget, 30, 60},
        {&LocalTreeWidget, 20, 60},
        {&LocalFilesWidget, 30, 60},
        {&RemoteStatusWidget, 50, 28},
        {&LocalStatusWidget, 49, 28}
    };

    HMODULE hLib = LoadLibrary(TEXT("Msftedit.dll"));
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
    
    WSADATA     WSAData = { 0 };
    if (FAILED(WSAStartup(MAKEWORD(2, 2), &WSAData))) {
        exit(-1);
    }

    CommandLine = pCmdLine;

    NdacClientConfig& ccfg = NdacClientConfig::GetInstance();
    ClusterClientManager& ccm = ClusterClientManager::GetInstance();
    threadPool::Initialize();
    threadPool::queueThread((void*)OsslClientHelper::Initialize, 0);
    ccm.LoadMembers();

    int i = 0;
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(pCmdLine);

    // TODO: Place code here.
    MSG msg;
    HACCEL hAccelTable;
    HKL hCurHKL = NULL;
    HKL hOldHKL = NULL;

    pWidgetPlacements = &placements[0];

    if (CommandLine && (wcslen(CommandLine) > 0)) {
        try {
            string s = ccfg.GetMyFilePath();
            Buffer to(s);
            SignalHandlerPointer previousHandler;
            std::vector<wchar_t*> pieces;
            splitStringW((wchar_t*)CommandLine, (wchar_t*)L" ", pieces);
            if (pieces.size() != 2) {
                exit(-1);
            }

            if (wcscmp((wchar_t*)L"/SandBoxedAuth", pieces.at(0)) != 0) {
                exit(-1);
            }
            
            SandBoxedState = NdacClientConfig::SandboxedState::INSIDE;
            previousHandler = signal(SIGINT, SignalHandler);
            previousHandler = signal(SIGTERM, SignalHandler);

            GetUtf8FromWchar(pieces.at(1), SandBoxAuthBuf);

            to.Append((void*)"\\CAFile.crt", strlen("\\CAFile.crt"));
            to.NullTerminate();
            CreateDirectoryA((char*)s.c_str(), 0);
            CopyFileA((char*)"C:\\Users\\WDAGUtilityAccount\\Downloads\\CAFile.crt", (char*)to, FALSE);

            GetGatewayIP(GatewayIP);
            FirewallBlockAllButThisIP(GatewayIP);
            MyLocalClient = new LocalClient();
            if (MyLocalClient) {
                threadPool::queueThread((void*)MonitorFirewall, (void*)GatewayIP);
            }
            else {
                exit(-1);//can't create this inside the sandbox so die
            }
        }
        catch (...) {
            exit(-1);
        }
    }

    hAppIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MAPSSCLIENT));
    InitTreeViewImageLists(hInstance);

    // Initialize global strings
    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_MAPSSCLIENT, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    //brushes
    hWindowBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
    hButtonBrush = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
    h3DlightBrush = CreateSolidBrush(GetSysColor(COLOR_3DLIGHT));

    // Perform application initialization:
    if (!InitInstance(hInstance, nCmdShow))
    {
        return FALSE;
    }

    hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MAPSSCLIENT));

    CreateClassifiedRootFolders();

    // Main message loop:
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
        MySystemShutdown();
    }
    else if (IsWinSandboxRunning()) {
        TerminateSandbox();
    }

    if (hAppFont)
        DeleteObject(hAppFont);

    if (hSmallFont)
        DeleteObject(hSmallFont);

    if (hShellImages)
        ImageList_Destroy(hShellImages);

    if (hInstalledAppsImgList)
        ImageList_Destroy(hInstalledAppsImgList);

    if (hFolderImgList)
        ImageList_Destroy(hFolderImgList);

    for (i = 0; i < (int)numIcons; i++)
    {
        if (hSmallIcons[i])
            DestroyIcon(hSmallIcons[i]);
    }

    if (hOldHKL)
        hOldHKL = ActivateKeyboardLayout(hOldHKL, KLF_SETFORPROCESS);

    if (RemoteFilesWidget.GetHWnd())
        ListView_DeleteAllItems(RemoteFilesWidget.GetHWnd());

    if (LocalFilesWidget.GetHWnd())
        ListView_DeleteAllItems(LocalFilesWidget.GetHWnd());

    if (AppsViewWidget.GetHWnd()) {
        ListView_DeleteAllItems(AppsViewWidget.GetHWnd());
    }

    TreeView_DeleteAllItems(RemoteTreeWidget.GetHWnd());
    TreeView_DeleteAllItems(LocalTreeWidget.GetHWnd());

    if (MyLocalClient) {
        delete MyLocalClient;
    }

    PrivateMaps.clear();

    DestroyWindow(hwndTT);
    Widget::Cleanup();

    FreeLibrary(hLib);

    ccfg.Finalize();

    DeleteObject(hWindowBrush);
    DeleteObject(hButtonBrush);
    DeleteObject(h3DlightBrush);

    ApplicationStopped = TRUE;

    while (NumWorkersRunning > 0) {
        std::this_thread::yield();
    }

    threadPool::Finalize();
    WSACleanup();

    return (int)msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = hSmallIcons[min(numIcons - 1, 109)];//LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SCADU));//
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;//MAKEINTRESOURCE(IDC_SCADU);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = hSmallIcons[min(numIcons - 1, 109)];//LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    HWND hWnd;

    hInst = hInstance; // Store instance handle in our global variable

    hWnd = CreateWindow(szWindowClass, (WCHAR*)L"AuthClient, RDC Inc.", WS_OVERLAPPEDWINDOW,
        0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, hInstance, NULL);

    if (!hWnd)
    {
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

BOOL InitTreeViewImageLists(HINSTANCE hInstance)
{
    BOOL bRc = FALSE;
    int i = 0;
    int limit = 0;
    WCHAR infoBuf[INFO_BUFFER_SIZE];

    memset(infoBuf, 0, sizeof(infoBuf));
    if (!GetSystemDirectory(infoBuf, INFO_BUFFER_SIZE)) {
        goto doneInitImages;
    }

    wcscat_s(infoBuf, INFO_BUFFER_SIZE, L"\\shell32.dll");//imageres.dll
    numIcons = ExtractIconEx(infoBuf, 0, NULL, NULL, 0);
    if (numIcons == 0) {
        goto doneInitImages;
    }

    if (numIcons > MAX_SMALL_ICONS) {
        goto doneInitImages;
    }

    memset(hSmallIcons, 0, sizeof(hSmallIcons));
    
    ExtractIconEx(infoBuf, 0, NULL, hSmallIcons, numIcons);

    // Create the image list. 
    if ((hShellImages = ImageList_Create(
        GetSystemMetrics(SM_CXICON) / 2,
        GetSystemMetrics(SM_CYICON) / 2,
        ILC_COLOR32 | ILC_MASK,
        numIcons,
        1)) == NULL) {
        goto doneInitImages;
    }

    ImageList_SetBkColor(hShellImages, RGB(255, 255, 255));

    for (i = 0; i < (int)numIcons; i++) {
        ImageList_AddIcon(hShellImages, hSmallIcons[i]);
    }

    // Fail if not all of the images were added. 
    if (ImageList_GetImageCount(hShellImages) < (int)numIcons)
        goto doneInitImages;

    if (hAppIcon) {
        hAppImages = ImageList_Create(
            GetSystemMetrics(SM_CXICON),// * 2,
            GetSystemMetrics(SM_CYICON),// * 2,
            ILC_COLOR32 | ILC_MASK,
            4,
            1);
        ImageList_SetBkColor(hAppImages, RGB(255, 255, 255));
        ImageList_AddIcon(hAppImages, hAppIcon);
        ImageList_AddIcon(hAppImages, hSmallIcons[min(numIcons - 1, CLASSIFIED_ICON)]);
        ImageList_AddIcon(hAppImages, hSmallIcons[min(numIcons - 1, START_ICON)]);
        ImageList_AddIcon(hAppImages, hSmallIcons[min(numIcons - 1, INSTALLER_ICON)]);
    }

    bRc = TRUE;

doneInitImages:

    if (bRc == FALSE)
    {
        for (i = 0; i < (int)numIcons; i++)
        {
            if (hSmallIcons[i])
                DestroyIcon(hSmallIcons[i]);
        }
        MessageBox(NULL, (WCHAR*)L"Error :Failed to load resources from shell.dll. Exiting application!", (WCHAR*)L"Error", MB_OK);
        exit(-1);
    }

    return bRc;
}

HIMAGELIST GetImageListForDirectoryFiles(WCHAR* wcPath, Buffer& files) {
    try {
        Buffer copy(files);
        HINSTANCE hInstance = 0;
        HIMAGELIST hImgL = 0;
        HICON hIcon = 0;
        wchar_t* pc = (wchar_t*)copy;
        wchar_t* tt = nullptr;
        wchar_t* ll = nullptr;

        hImgL = ImageList_Create(
            GetSystemMetrics(SM_CXICON),// * 2,
            GetSystemMetrics(SM_CYICON),// * 2,
            ILC_COLOR32 | ILC_MASK,
            1, 1);
        ImageList_SetBkColor(hImgL, RGB(255, 255, 255));

        tt = wcstok_s(pc, L"\n", &ll);
        while (tt) {
            WCHAR out[MAX_PATH];
            WORD piIcon = 0;
            hIcon = 0;
            if (FindExecutable(tt, wcPath, out) > MIN_SUCCESS) {
                hIcon = ExtractAssociatedIcon(hInst, out, &piIcon);
            }
            if (hIcon) {
                ImageList_AddIcon(hImgL, hIcon);
            }
            else {
                if (wcsstr(tt, L".classified")) {
                    ImageList_AddIcon(hImgL, hSmallIcons[min(numIcons - 1, CLASSIFIED_ICON)]);
                }
                else {
                    ImageList_AddIcon(hImgL, hSmallIcons[min(numIcons - 1, UNKNOWN_ICON)]);
                }
            }

            tt = wcstok_s(0, L"\n", &ll);
        }

        return hImgL;
    }
    catch (...) {
        return 0;
    }
}

void AddRemoteClassifiedTreeItem(HTREEITEM hti, wchar_t** tt, wchar_t** ll, int level)
{
    TVITEM							tvi;
    TVINSERTSTRUCT					tvins;
    HTREEITEM						hCur;
    int								i = 0;

    tvi.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;

    // Set the text of the item. 
    Buffer r;
    tvi.pszText = *tt;
    tvi.cchTextMax = (int)wcslen(tvi.pszText);//sizeof(tvi.pszText)/sizeof(tvi.pszText[0]); 

    // Assume the item is not a parent item, so give it a 
    // document image.
    tvi.iImage = min((int)numIcons - 1, 37);
    tvi.iSelectedImage = min((int)numIcons - 1, 37);

    // Save the heading level in the item's application-defined 
    // data area. 
    tvi.lParam = (LPARAM)level;
    tvins.item = tvi;
    tvins.hInsertAfter = hti;
    if (level == 0)
        tvins.hParent = TVI_ROOT;
    else
        tvins.hParent = hti;

    // Add the item to the tree-view control. 
    //hCur = (HTREEITEM)SendMessage( hwndOUnitTree, TVM_INSERTITEM, 0, (LPARAM)(LPTVINSERTSTRUCT)&tvins );
    hCur = TreeView_InsertItem(RemoteTreeWidget.GetHWnd(), (LPARAM)(LPTVINSERTSTRUCT)&tvins);

    *tt = wcstok_s(0, L"\t\n", ll);
    while (*tt) {
        if (wcscmp(*tt, L"<DIR>") == 0) {
            *tt = wcstok_s(0, L"\t\n", ll);
            if (*tt) {
                AddRemoteClassifiedTreeItem(hCur, tt, ll, level + 1);
            }
        }
        else if (wcscmp(*tt, L"</DIR>") == 0) {
            break;
        }
        *tt = wcstok_s(0, L"\t\n", ll);
    }

    TreeView_SetTextColor(RemoteTreeWidget.GetHWnd(), RGB(0, 0, 255));
    TreeView_Expand(RemoteTreeWidget.GetHWnd(), hCur, TVM_EXPAND);

}

//http://msdn.microsoft.com/en-us/library/windows/desktop/hh298347(v=vs.85).aspx
void BuildRemoteClassifiedTree()
{
    try {
        HTREEITEM hRoot = (HTREEITEM)TVI_FIRST;
        Buffer temp(CmdTree);
        wchar_t* pc = (wchar_t*)temp;
        wchar_t* tt = nullptr;
        wchar_t* ll = nullptr;

        TreeView_DeleteAllItems(RemoteTreeWidget.GetHWnd());

        tt = wcstok_s(pc, L"\t\n", &ll);
        if (tt) {
            tt = wcstok_s(0, L"\t\n", &ll);
        }

        if (tt) {
            AddRemoteClassifiedTreeItem(hRoot, (wchar_t**)&tt, (wchar_t**)&ll, 0);
        }
    }
    catch (...) {
        return;
    }
}

bool GetLocalClassifiedFolders(Buffer& bTree)
{
    try {
        wchar_t perm[MAX_NAME];
        size_t requiredSize = 0;
        wchar_t start[16] = L"<DIR>\n";
        size_t szStart = 0;
        wchar_t end[16] = L"</DIR>\n";
        size_t szEnd = 0;

        if (SUCCEEDED(StringCbLengthW(start, 16, &szStart))) {
            if (SUCCEEDED(StringCbLengthW(end, 16, &szEnd))) {

                _wgetenv_s(&requiredSize, 0, 0, L"APPDATA");
                if (requiredSize > 0)
                {
                    size_t sz = 0;
                    Buffer bEnv(requiredSize * sizeof(wchar_t));
                    _wgetenv_s(&requiredSize, (wchar_t*)bEnv, requiredSize, L"APPDATA");

                    if (SUCCEEDED(StringCchCopy(perm, MAX_PATH, (wchar_t*)bEnv)) &&
                        SUCCEEDED(StringCchCat(perm, MAX_PATH, L"\\classified")) &&
                        SUCCEEDED(StringCbLength(perm, MAX_PATH, &sz))) {
                        bTree.Append((void*)start, szStart);
                        bTree.Append((void*)perm, sz);
                        bTree.Append((void*)L"\n", sizeof(wchar_t));
                        GetDirectoryTree(perm, bTree, 1);
                        bTree.Append((void*)end, szEnd);
                        bTree.NullTerminate_w();
                        return true;
                    }
                
                }
            }
        }
    }
    catch (...) {
        bTree.Clear();
        return false;
    }

    return false;
}

void AddLocalClassifiedTreeItem(HTREEITEM hti, wchar_t** tt, wchar_t** ll, int level)
{
    TVITEM							tvi;
    TVINSERTSTRUCT					tvins;
    HTREEITEM						hCur;
    int								i = 0;

    tvi.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;

    // Set the text of the item. 
    Buffer r;
    tvi.pszText = *tt;
    tvi.cchTextMax = (int)wcslen(tvi.pszText);//sizeof(tvi.pszText)/sizeof(tvi.pszText[0]); 

    // Assume the item is not a parent item, so give it a 
    // document image.
    tvi.iImage = min((int)numIcons - 1, 37);
    tvi.iSelectedImage = min((int)numIcons - 1, 37);

    // Save the heading level in the item's application-defined 
    // data area. 
    tvi.lParam = (LPARAM)level;
    tvins.item = tvi;
    tvins.hInsertAfter = hti;
    if (level == 0)
        tvins.hParent = TVI_ROOT;
    else
        tvins.hParent = hti;

    // Add the item to the tree-view control. 
    //hCur = (HTREEITEM)SendMessage( hwndOUnitTree, TVM_INSERTITEM, 0, (LPARAM)(LPTVINSERTSTRUCT)&tvins );
    hCur = TreeView_InsertItem(LocalTreeWidget.GetHWnd(), (LPARAM)(LPTVINSERTSTRUCT)&tvins);

    *tt = wcstok_s(0, L"\t\n", ll);
    while (*tt) {
        if (wcscmp(*tt, L"<DIR>") == 0) {
            *tt = wcstok_s(0, L"\t\n", ll);
            if (*tt) {
                AddLocalClassifiedTreeItem(hCur, tt, ll, level + 1);
            }
        }
        else if (wcscmp(*tt, L"</DIR>") == 0) {
            break;
        }
        *tt = wcstok_s(0, L"\t\n", ll);
    }

    TreeView_SetTextColor(LocalTreeWidget.GetHWnd(), RGB(0, 0, 255));
    TreeView_Expand(LocalTreeWidget.GetHWnd(), hCur, TVM_EXPAND);

}

//http://msdn.microsoft.com/en-us/library/windows/desktop/hh298347(v=vs.85).aspx
void BuildLocalClassifiedTree()
{
    try {
        HTREEITEM hRoot = (HTREEITEM)TVI_FIRST;
        Buffer bTree;
        wchar_t* pc;
        wchar_t* tt = nullptr;
        wchar_t* ll = nullptr;

        GetLocalClassifiedFolders(bTree);
        pc = (wchar_t*)bTree;

        TreeView_DeleteAllItems(LocalTreeWidget.GetHWnd());

        tt = wcstok_s(pc, L"\t\n", &ll);
        if (tt) {
            tt = wcstok_s(0, L"\t\n", &ll);
        }

        if (tt) {
            AddLocalClassifiedTreeItem(hRoot, (wchar_t**)&tt, (wchar_t**)&ll, 0);
        }
    }
    catch (...) {
        return;
    }
}

bool GetUserEnv(Buffer& bEnvironment)
{
    try {
        size_t requiredSize = 0;
        _wgetenv_s(&requiredSize, 0, 0, L"APPDATA");
        if (requiredSize > 0)
        {
            Buffer bEnv(requiredSize * sizeof(WCHAR) + sizeof(WCHAR));
            _wgetenv_s(&requiredSize, (WCHAR*)bEnv, requiredSize, L"APPDATA");
            bEnvironment.Clear();
            bEnvironment.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
            return true;
        }
    }
    catch (...) {
        bEnvironment.Clear();
        return false;
    }

    return false;
}

bool CreateClassifiedFolders(Buffer& bPerm, Buffer& bTemp)
{
    try {
        size_t requiredSize = 0;
        _wgetenv_s(&requiredSize, 0, 0, L"APPDATA");
        if (requiredSize > 0)
        {
            wchar_t* pc = nullptr;
            wchar_t* tt = nullptr;
            wchar_t* ll = nullptr;
            Buffer temp(SelectedRemoteFolder);
            Buffer bEnv(requiredSize * sizeof(WCHAR) + sizeof(WCHAR));
            _wgetenv_s(&requiredSize, (WCHAR*)bEnv, requiredSize, L"APPDATA");
            bPerm.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
            bTemp.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));

            pc = (WCHAR*)temp;
            tt = wcstok_s(pc, L"\\", &ll);
            while (tt && (wcscmp(tt, L"classified") != 0)) {
                tt = wcstok_s(0, L"\\", &ll);
            }

            while (tt) {
                bPerm.Append((void*)L"\\", sizeof(WCHAR));
                bPerm.Append((void*)tt, wcslen(tt) * sizeof(WCHAR));
                Buffer bDir = bPerm;
                bDir.NullTerminate_w();
                if (!CreateDirectory((WCHAR*)bDir, 0)) {
                    if (GetLastError() != ERROR_ALREADY_EXISTS) {
                        return false;
                    }
                }
                tt = wcstok_s(0, L"\\", &ll);
            }

            return true;
        }
    }
    catch (...) {
        bPerm.Clear();
        bTemp.Clear();
        return false;
    }

    return false;
}

int GetRemoteDocumentTree()
{
    try {
        TLSClientContext client;
        Buffer resp;
        if (RequestAuthorization(client, nullptr, CMD_GET_DOCUMENT_TREE, resp, true)) {
            if (resp.Size() > sizeof(ResponseHeader)) {
                ResponseHeader* prh = (ResponseHeader*)resp;
                if (resp.Size() == (prh->szData + sizeof(ResponseHeader))) {
                    char* pChar = (char*)resp + sizeof(ResponseHeader);
                    CmdTree.Clear();
                    CmdTree.Append((void*)pChar, prh->szData);
                    BuildRemoteClassifiedTree();
                    BuildLocalClassifiedTree();
                }
            }
            {
                Buffer upn;
                client.GetUPNSubjectAltName(upn);
                upn.Prepend((void*)"  Authenticated as: ", strlen((char*)"  Authenticated as: "));
                upn.NullTerminate();
                SetWindowTextA(UserPrincipalWidget.GetHWnd(), (char*)upn);
            }
        }
    }
    catch (...) {
        CmdTree.Clear();
    }

    return 0;
}

bool AuthenticateToProxy()
{
    try {
        if (MyLocalClient) {
            CommandHeader ch;
            Buffer bCmd;
            Buffer bResponse;
            ch.command = Commands::CMD_OOB_AUTHENTICATE;
            ch.szData = SandBoxAuthBuf.Size();
            bCmd.Append((void*)&ch, sizeof(ch));
            bCmd.Append(SandBoxAuthBuf);
            if (MyLocalClient->SendToProxy(bCmd, SandBoxAuthBuf) == RSP_SUCCESS) {
                return true;
            }
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

bool GetUserCertFromProxy()
{
    try {
        if (MyLocalClient) {
            CommandHeader ch;
            Buffer bCmd;
            Buffer bResponse;
            ch.command = Commands::CMD_OOB_GET_SC_CERT;
            ch.szData = 0;
            bCmd.Append((void*)&ch, sizeof(ch));
            if (MyLocalClient->SendToProxy(bCmd, bResponse) == RSP_SUCCESS) {
                Buffer upn;
                Certificate cert(bResponse);
                cert.GetUPNSubjectAltName(upn);
                upn.Prepend((void*)"  Authenticated as: ", strlen((char*)"  Authenticated as: "));
                upn.NullTerminate();
                SetWindowTextA(UserPrincipalWidget.GetHWnd(), (char*)upn);
                return true;
            }
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

void
DeleteIfNotVerified(Buffer& bFile) {
    try {
        bool bVerified = false;
        DocHandler dh;

        if (dh.OpenDocument((wchar_t*)bFile)) {
            DilithiumKeyPair& dpk = TLSContext::GetDilithium();
            bVerified = dh.TimeStampVerify(dpk);
            dh.Close();
        }

        if (!bVerified) {
            DeleteFile((wchar_t*)bFile);
        }
    }
    catch (...) {
        return;
    }

    return;
}

void DeleteUnproctedFilesFromFolder(Buffer bDir)
{
    try {
        Buffer bFiles;
        Buffer bSubDirs;
        wchar_t* pc = nullptr;
        wchar_t* tt = nullptr;
        wchar_t* ll = nullptr;

        if (wcsstr((wchar_t*)bDir, L"SoftwareInstallers")) {
            return;
        }

        GetDirectoryContents((wchar_t*)bDir, bFiles);
        if (bFiles.Size() > 0) {
            pc = (wchar_t*)bFiles;
            tt = wcstok_s(pc, L"\t\n", &ll);
            while (tt) {
                Buffer b(bDir);
                b.Append((void*)L"\\", sizeof(WCHAR));
                b.Append((void*)tt, wcslen(tt) * sizeof(WCHAR));
                b.NullTerminate_w();
                if (wcsstr(tt, L".classified")) {
                    DeleteIfNotVerified(b);
                }
                else if (wcsstr(tt, L".csr")) {
                    Buffer c;
                    GetUtf8FromWchar((WCHAR*)b, c);
                    if (!VerifyCertRequestFile((char*)c)) {
                        DeleteFile((wchar_t*)b);
                    }
                }
                else {
                    DeleteFile((wchar_t*)b);
                }

                tt = wcstok_s(0, L"\t\n", &ll);
            }
        }

        tt = nullptr;
        ll = nullptr;
        GetSubDirectories((wchar_t*)bDir, bSubDirs);
        if (bSubDirs.Size() > 0) {
            pc = (wchar_t*)bSubDirs;
            tt = wcstok_s(pc, L"\t\n", &ll);
            while (tt) {
                Buffer b(bDir);
                b.Append((void*)L"\\", sizeof(WCHAR));
                b.Append((void*)tt, wcslen(tt) * sizeof(WCHAR));
                DeleteUnproctedFilesFromFolder(b);
                tt = wcstok_s(0, L"\t\n", &ll);
            }
        }
    }
    catch (...) {
        return;
    }
}

void DeleteAllUnprotectedFiles()
{
    try {
        Buffer bDir;
        if (GetLocalClassifiedFolder(bDir)) {
            DeleteUnproctedFilesFromFolder(bDir);
        }
    }
    catch (...) {
        return;
    }

    return;
}

int
UpdateProgress(HWND hWnd) {
    SendMessage(hWnd, PBM_STEPIT, 0, 0);
#ifdef _DEBUG
    //	Sleep(50);
#endif
    return 0;
}

void
UpdateProgressText(WCHAR* pwcText) {
    if (pwcText) {
        SetWindowText(ProgressTextWidget.GetHWnd(), pwcText);
    }
}

bool
IsLocallySelectedBusy(
    Buffer& bSelected
)
{
    return false;
}

bool
WhereTo(AuthorizationResponse* pAR, Buffer& bUPN, Buffer& bFolderFile) {
    try {
        WCHAR wcBuf[MAX_LINE];

        if (!pAR) {
            return false;
        }

        if (!GetLocalClassifiedFolder(bFolderFile)) {
            return false;
        }

        memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
        swprintf_s(wcBuf, MAX_LINE, L"%s\\Drafts", (wchar_t*)bFolderFile);
        if (!CreateDirectory((WCHAR*)wcBuf, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }

        memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
        swprintf_s(wcBuf, MAX_LINE, L"%s\\Drafts\\%S", (wchar_t*)bFolderFile, pAR->docMAC.mcs_desc[0]);
        if (!CreateDirectory((WCHAR*)wcBuf, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
        bFolderFile.Clear();
        bFolderFile.Append((void*)wcBuf, wcslen(wcBuf) * sizeof(WCHAR));

        memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
        swprintf_s(wcBuf, MAX_LINE, L"%s\\%S", (wchar_t*)bFolderFile, pAR->docMAC.mls_desc);
        if (!CreateDirectory((WCHAR*)wcBuf, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
        bFolderFile.Clear();
        bFolderFile.Append((void*)wcBuf, wcslen(wcBuf) * sizeof(WCHAR));

        memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
        swprintf_s(wcBuf, MAX_LINE, L"%s\\%S", (wchar_t*)bFolderFile, (char*)bUPN);
        if (!CreateDirectory((WCHAR*)wcBuf, 0)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
        bFolderFile.Clear();
        bFolderFile.Append((void*)wcBuf, wcslen(wcBuf) * sizeof(WCHAR));

        bFolderFile.Append((void*)L"\\", sizeof(WCHAR));
        bFolderFile.Append(SelectedLocalFile);
        bFolderFile.Append((void*)L".classified", wcslen(L".classified") * sizeof(WCHAR));
        bFolderFile.NullTerminate_w();

        return true;
    }
    catch (...) {
        bFolderFile.Clear();
        return false;
    }
}

void
GetRemoteFileNames() {
    try {
        bool isSwInstaller = false;
        HTREEITEM Parent = 0;
        TVITEM tvitem;
        Buffer wcName;
        WCHAR temp[1024];
        int max = 1023;
        WCHAR* pwcText = 0;
        HTREEITEM Selected = TreeView_GetSelection(RemoteTreeWidget.GetHWnd());
        if (!Selected)
        {
            return;
        }

        max = sizeof(temp) / sizeof(WCHAR) - 1;

        ListView_DeleteAllItems(RemoteFilesWidget.GetHWnd());
        memset(temp, 0, sizeof(temp));
        // Get the text for the item.
        tvitem.mask = TVIF_TEXT;
        tvitem.hItem = Selected;
        tvitem.pszText = temp;
        tvitem.cchTextMax = max;
        TreeView_GetItem(RemoteTreeWidget.GetHWnd(), &tvitem);
        temp[max] = 0;
        wcName.Append((void*)temp, wcslen(temp) * sizeof(WCHAR));
        Parent = TreeView_GetParent(RemoteTreeWidget.GetHWnd(), Selected);
        if (wcscmp(temp, L"SoftwareInstallers") == 0) {
            isSwInstaller = true;
        }
        while (Parent)
        {
            memset(temp, 0, sizeof(temp));
            tvitem.hItem = Parent;
            tvitem.pszText = temp;
            tvitem.cchTextMax = sizeof(temp) / sizeof(WCHAR) - 1;
            TreeView_GetItem(RemoteTreeWidget.GetHWnd(), &tvitem);
            wcName.Prepend((void*)L"\\", sizeof(WCHAR));
            wcName.Prepend((void*)temp, wcslen(temp) * sizeof(WCHAR));
            Parent = TreeView_GetParent(RemoteTreeWidget.GetHWnd(), Parent);
        }

        {
            TLSClientContext client;
            bool bRc = false;
            AuthorizationRequest ar;
            Buffer resp;

            SelectedRemoteFolder = wcName;
            memset(&ar, 0, sizeof(ar));
            memcpy((void*)ar.docMAC.mls_doc_name, (wchar_t*)wcName, wcName.Size());
            if (RequestAuthorization(client, &ar, CMD_GET_DOCUMENT_NAMES, resp, true)) {
                if (resp.Size() > sizeof(ResponseHeader)) {
                    ResponseHeader* prh = (ResponseHeader*)resp;
                    if (resp.Size() == (prh->szData + sizeof(ResponseHeader))) {
                        LVITEM lvI;
                        char* pV = (char*)resp + sizeof(ResponseHeader);
                        wchar_t* pc = (wchar_t*)pV;
                        wchar_t* tt = nullptr;
                        wchar_t* ll = nullptr;
                        tt = wcstok_s(pc, L"\n", &ll);
                        while (tt) {
                            Buffer c;
                            wchar_t* pwcMsg = tt;
                            lvI.pszText = pwcMsg; // Sends an LVN_GETDISPINFO message.
                            lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_STATE;
                            lvI.stateMask = 0;
                            lvI.iSubItem = 0;
                            lvI.state = 0;
                            if (isSwInstaller) {
                                lvI.iItem = min(numIcons - 1, 3);
                                lvI.iImage = min(numIcons - 1, 3);
                            }
                            else if (wcsstr(SelectedRemoteFolder, L"\\Declassified\\")) {
                                lvI.iItem = min(numIcons - 1, 3);
                                lvI.iImage = min(numIcons - 1, 3);
                            }
                            else {
                                lvI.iItem = min(numIcons - 1, 1);
                                lvI.iImage = min(numIcons - 1, 1);
                            }

                            ListView_InsertItem(RemoteFilesWidget.GetHWnd(), &lvI);
                            tt = wcstok_s(0, L"\n", &ll);

                        }
                    }
                }
            }
        }
    }
    catch (...) {
        return;
    }
}

void*
EncryptProc(void* args) {
    try {
        struct _stat sbuf;
        bool bRc = false;
        DocHandler dh;
        TLSClientContext client;
        Buffer bEnv;
        Buffer resp;
        Buffer bSelected(SelectedLocalFolder);
        Buffer bOut;

        if (SandBoxedState == NdacClientConfig::SandboxedState::UNKNOWN) {
            return 0;
        }

        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedLocalFile);
        bSelected.NullTerminate_w();

        _wstat((wchar_t*)bSelected, &sbuf);
        if (sbuf.st_size > 0)
        {
            int max = 100;
            int step = 1;
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETRANGE, 0, MAKELPARAM(0, max));
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETSTEP, (WPARAM)step, 0);
        }

        if (GetUserEnv(bEnv) &&
            RequestAuthorization(client, nullptr, CMD_GET_MLS_MCS_AES_ENC_KEY, resp, true)) {
            if (resp.Size() > sizeof(ResponseHeader)) {
                ResponseHeader* prh = (ResponseHeader*)resp;
                if (resp.Size() == (prh->szData + sizeof(ResponseHeader))) {
                    char* pChar = (char*)resp + sizeof(ResponseHeader);
                    AuthorizationResponse* pAR = (AuthorizationResponse*)pChar;
                    Buffer bUPN;

                    std::shared_ptr<NotifyView> nv = std::make_shared<NotifyView>();
                    nv->function = UpdateProgress;
                    nv->hWnd = ProgressBarWidget.GetHWnd();

                    SetLocalStatus((WCHAR*)L"Starting to encrypt...\n", true);
                    if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
                        CommandHeader ch;
                        Buffer bResponse;
                        Buffer bCmd;
                        ch.command = Commands::CMD_OOB_GET_SC_CERT;
                        ch.szData = 0;
                        bCmd.Append((void*)&ch, sizeof(ch));
                        if (MyLocalClient->SendToProxy(bCmd, bResponse) == RSP_SUCCESS) {
                            Certificate cert(bResponse);
                            cert.GetUPNSubjectAltName(bUPN);
                        }
                    }
                    else {
                        client.GetUPNSubjectAltName(bUPN);
                    }
                    WhereTo(pAR, bUPN, bOut);

                    dh.SetAuthResponse(*pAR);
                    bRc = dh.ProtectFile(
                        (wchar_t*)bSelected,
                        (wchar_t*)bOut,
                        (wchar_t*)L"Windows",
                        nv);
                }////here
            }
        }
        {
            WCHAR wcBuf[MAX_LINE];
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            swprintf_s(wcBuf, MAX_LINE,
                L"%s\r\n%s\r\nto\r\n%s\r\n",
                bRc ? L"Success encrypting" : L"Failed encrypting",
                (wchar_t*)bSelected,
                (wchar_t*)bOut);
            SetLocalStatus((WCHAR*)wcBuf, true);
            if (bRc) {
                DeleteFileW((wchar_t*)bSelected);
                BuildLocalClassifiedTree();
            }
            else {
                DeleteFileW((wchar_t*)bOut);
            }
        }

        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        
        ShowLocalFiles();
    }
    catch (...) {
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        return 0;
    }

    return 0;
}

void*
DecryptProc(void* args) {
    try {
        WCHAR wcBuf[MAX_LINE];
        struct _stat sbuf;
        DocHandler dh;
        TLSClientContext client;
        bool bRc = false;
        AuthorizationRequest ar;
        Buffer bSelected(SelectedLocalFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedLocalFile);
        bSelected.NullTerminate_w();

        _wstat((wchar_t*)bSelected, &sbuf);
        if (sbuf.st_size > 0)
        {
            int max = 100;
            int step = 1;
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETRANGE, 0, MAKELPARAM(0, max));
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETSTEP, (WPARAM)step, 0);
        }

        memset(&ar, 0, sizeof(ar));
        if (dh.OpenDocument((wchar_t*)bSelected)) {
            if (dh.GetAuthRequest(ar)) {
                Buffer resp;
                if (RequestAuthorization(client, &ar, CMD_GET_MLS_MCS_AES_DEC_KEY, resp, true)) {
                    if (resp.Size() > sizeof(ResponseHeader)) {
                        ResponseHeader* prh = (ResponseHeader*)resp;
                        if (resp.Size() == (prh->szData + sizeof(ResponseHeader))) {
                            char* pChar = (char*)resp + sizeof(ResponseHeader);
                            AuthorizationResponse* pAR = (AuthorizationResponse*)pChar;
                            dh.SetAuthResponse(*pAR);
                            Buffer out(bSelected);
                            WCHAR* pwc = wcsstr((WCHAR*)out, L".classified");
                            if (pwc) {
                                FILE* fp = 0;
                                pwc[0] = 0;
                                fp = f_open_u((WCHAR*)out, (WCHAR*)L"wb");
                                if (fp) {
                                    std::shared_ptr<NotifyView> nv = std::make_shared<NotifyView>();
                                    nv->function = UpdateProgress;
                                    nv->hWnd = ProgressBarWidget.GetHWnd();
                                    SetLocalStatus((WCHAR*)L"Starting to decrypt...\n", true);
                                    bRc = dh.DecryptVerify(fp, nv);
                                    fclose(fp);
                                }
                            }
                            {
                                memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
                                swprintf_s(wcBuf, MAX_LINE,
                                    L"%s\r\n%s\r\nto\r\n%s\r\n",
                                    bRc ? L"Success decrypting" : L"Failed decrypting",
                                    (wchar_t*)bSelected,
                                    (wchar_t*)out);
                                SetLocalStatus((WCHAR*)wcBuf, true);
                                if (bRc) {
                                    ShowLocalFiles();
                                }
                            }
                        }
                    }
                }
                else {
                    ResponseHeader* prh = (ResponseHeader*)resp;
                    memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
                    swprintf_s(wcBuf, MAX_LINE, L"Failed to authorize decryption of %s\r\nResponse = %s(%d)\r\n",
                        (wchar_t*)bSelected, wcErrorStrings[prh->response], prh->response);
                    SetLocalStatus((WCHAR*)wcBuf, true);
                }
            }
        }
        else {
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            swprintf_s(wcBuf, MAX_LINE, L"Failed to open %s\r\n", (wchar_t*)bSelected);
            SetLocalStatus((WCHAR*)wcBuf, true);
        }

        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        
        ShowLocalFiles();
    }
    catch (...) {
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        return 0;
    }

    return 0;
}

void*
VerifyProc(void* args) {
    try {
        WCHAR wcBuf[MAX_LINE];
        struct _stat sbuf;
        DocHandler dh;
        TLSClientContext client;
        AuthorizationRequest ar;
        Buffer bSelected(SelectedLocalFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedLocalFile);
        bSelected.NullTerminate_w();

        _wstat((wchar_t*)bSelected, &sbuf);
        if (sbuf.st_size > 0)
        {
            int max = 100;
            int step = 1;
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETRANGE, 0, MAKELPARAM(0, max));
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETSTEP, (WPARAM)step, 0);
        }

        memset(&ar, 0, sizeof(ar));
        if (dh.OpenDocument((wchar_t*)bSelected)) {
            if (dh.GetAuthRequest(ar)) {
                Buffer resp;
                if (RequestAuthorization(client, &ar, CMD_GET_MLS_MCS_AES_DEC_KEY, resp, true)) {
                    if (resp.Size() > sizeof(ResponseHeader)) {
                        ResponseHeader* prh = (ResponseHeader*)resp;
                        if (resp.Size() == (prh->szData + sizeof(ResponseHeader))) {
                            char* pChar = (char*)resp + sizeof(ResponseHeader);
                            AuthorizationResponse* pAR = (AuthorizationResponse*)pChar;
                            std::shared_ptr<NotifyView> nv = std::make_shared<NotifyView>();
                            nv->function = UpdateProgress;
                            nv->hWnd = ProgressBarWidget.GetHWnd();
                            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
                            dh.SetAuthResponse(*pAR);
                            SetLocalStatus((WCHAR*)L"Starting to verify...\n", true);
                            dh.DecryptVerify(nullptr, nv);
                            dh.PrintOn(wcBuf, MAX_LINE - 1);
                            SetLocalStatus((WCHAR*)wcBuf, true);
                        }
                    }
                }
                else {
                    ResponseHeader* prh = (ResponseHeader*)resp;
                    memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
                    swprintf_s(wcBuf, MAX_LINE, L"Failed to authorize verification of %s\r\nResponse = %s(%d)\r\n",
                        (wchar_t*)bSelected, wcErrorStrings[prh->response], prh->response);
                    SetLocalStatus((WCHAR*)wcBuf, true);
                }
            }
        }
        else {
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            swprintf_s(wcBuf, MAX_LINE, L"Failed to open %s\r\n", (wchar_t*)bSelected);
            SetLocalStatus((WCHAR*)wcBuf, true);
        }

        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        
        return 0;
    }
    catch (...) {
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        return 0;
    }
}

void*
UploadProc(void* args) {
    try {
        struct _stat sbuf;
        TLSClientContext client;
        Responses rsp = RSP_INTERNAL_ERROR;
        AuthorizationRequest ar;
        DocHandler dh;
        Buffer bSelected(SelectedLocalFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedLocalFile);
        bSelected.NullTerminate_w();

        _wstat((wchar_t*)bSelected, &sbuf);
        if (sbuf.st_size > 0)
        {
            int max = 100;
            int step = 1;
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETRANGE, 0, MAKELPARAM(0, max));
            SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETSTEP, (WPARAM)step, 0);
        }

        dh.OpenDocument((wchar_t*)bSelected);
        if (dh.GetAuthRequest(ar)) {
            Buffer resp;
            if (RequestAuthorization(client, &ar, CMD_UPLOAD_DOCUMENT, resp, false)) {
                std::shared_ptr<NotifyView> nv = std::make_shared<NotifyView>();
                nv->function = UpdateProgress;
                nv->hWnd = ProgressBarWidget.GetHWnd();
                SetLocalStatus((WCHAR*)L"Starting to upload...\n", true);
                if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
                    rsp = dh.SendDocumentToProxy(MyLocalClient->GetSock(), nv);
                }
                else {
                    rsp = dh.SendDocument(client, nv);
                }
                client.EndConnection();
            }
        }
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        
        {
            WCHAR wcBuf[MAX_LINE];
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            swprintf_s(wcBuf, MAX_LINE,
                L"%s\r\n%s\r\nresp = %d\r\n",
                (rsp == RSP_SUCCESS) ? L"Success uploading" : L"Failed uploading",
                (wchar_t*)bSelected, rsp);
            SetLocalStatus((WCHAR*)wcBuf, true);
            if (rsp == RSP_SUCCESS) {
                //   GetRemoteDocumentTree();
            }
        }

        return 0;
    }
    catch (...) {
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        return 0;
    }
}

void*
MonitorRemoteVerifyProc(void* args) {
    while (OperationInProgress) {
        Sleep(500);
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_STEPIT, 0, 0);
    }
    SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
    return 0;
}

void*
AboutMe(void* args) {
    try {
        bool bRc = false;
        DocHandler dh;
        TLSClientContext client;
        Buffer bEnv;
        Buffer resp;

        if (SandBoxedState == NdacClientConfig::SandboxedState::UNKNOWN) {
            return 0;
        }

        if (GetUserEnv(bEnv) &&
            RequestAuthorization(client, nullptr, CMD_GET_MLS_MCS_AES_ENC_KEY, resp, true)) {
            if (resp.Size() > sizeof(ResponseHeader)) {
                ResponseHeader* prh = (ResponseHeader*)resp;
                if (resp.Size() == (prh->szData + sizeof(ResponseHeader))) {
                    char* pChar = (char*)resp + sizeof(ResponseHeader);
                    AuthorizationResponse* pAR = (AuthorizationResponse*)pChar;
                    Buffer bUPN;

                    if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
                        CommandHeader ch;
                        Buffer bResponse;
                        Buffer bCmd;
                        ch.command = Commands::CMD_OOB_GET_SC_CERT;
                        ch.szData = 0;
                        bCmd.Append((void*)&ch, sizeof(ch));
                        if (MyLocalClient->SendToProxy(bCmd, bResponse) == RSP_SUCCESS) {
                            Certificate cert(bResponse);
                            cert.GetUPNSubjectAltName(bUPN);
                        }
                    }
                    else {
                        client.GetUPNSubjectAltName(bUPN);
                    }
                    bUPN.Prepend((void*)"UPN = ", 6);
                    bUPN.EOLN();
                    bUPN.Append((void*)"MLS = ", 6);
                    bUPN.Append((void*)pAR->docMAC.mls_desc, strlen(pAR->docMAC.mls_desc));
                    bUPN.EOLN();
                    bUPN.Append((void*)"MCS = ", 6);
                    for (int i = 0; i < MAX_MCS_LEVEL; i++)
                        if (strlen(pAR->docMAC.mcs_desc[i]) > 0) {
                            bUPN.Append((void*)pAR->docMAC.mcs_desc[i], strlen(pAR->docMAC.mcs_desc[i]));
                            bUPN.EOLN();
                            bUPN.Append((void*)"            ", 12);
                        }
                    bUPN.EOLN();
                    bUPN.NullTerminate();
                    MessageBoxA(NULL, (char*)bUPN, "About Me", MB_OK);
                }//here
            }
        }
    }
    catch (...) {
        return 0;
    }

    return 0;
}

void*
RemoteVerifyProc(void* args) {
    try {
        WCHAR wcBuf[MAX_LINE];
        Responses response = RSP_NULL;
        TLSClientContext client;
        AuthorizationRequest ar;
        Buffer resp;
        Buffer bSelected(SelectedRemoteFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedRemoteFile);
        bSelected.NullTerminate_w();
        memset(&ar, 0, sizeof(ar));
        memcpy((void*)ar.docMAC.mls_doc_name, (wchar_t*)bSelected, bSelected.Size());

        RequestAuthorization(client, &ar, CMD_VERIFY_DOCUMENT, resp, true);

        {
            ResponseHeader* prh = (ResponseHeader*)resp;
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            if (prh) {
                swprintf_s(wcBuf, MAX_LINE, L"%s %s\r\nResponse = %s(%d)\r\n",
                    (prh->response == RSP_SUCCESS) ? L"VERIFIED," : L"NOT VERIFIED,",
                    (wchar_t*)bSelected, wcErrorStrings[prh->response], prh->response);
            }
            SetRemoteStatus((WCHAR*)wcBuf, true);
        }

        return 0;
    }
    catch (...) {
        return 0;
    }
}

void*
PublishProc(void* args) {
    try {
        WCHAR wcBuf[MAX_LINE];
        Responses response = RSP_NULL;
        TLSClientContext client;
        AuthorizationRequest ar;
        Buffer resp;
        Buffer bSelected(SelectedRemoteFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedRemoteFile);
        bSelected.NullTerminate_w();
        memset(&ar, 0, sizeof(ar));
        memcpy((void*)ar.docMAC.mls_doc_name, (wchar_t*)bSelected, bSelected.Size());

        RequestAuthorization(client, &ar, CMD_PUBLISH_DOCUMENT, resp, true);

        {
            ResponseHeader* prh = (ResponseHeader*)resp;
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            if (prh) {
                swprintf_s(wcBuf, MAX_LINE, L"%s %s\r\nResponse = %s(%d)\r\n",
                    (prh->response == RSP_SUCCESS) ? L"PUBLISHED," : L"NOT PUBLSHED,",
                    (wchar_t*)bSelected, wcErrorStrings[prh->response], prh->response);
                response = prh->response;
            }
            SetRemoteStatus((WCHAR*)wcBuf, true);
        }
        
        GetRemoteFileNames();

        return 0;
    }
    catch (...) {
        return 0;
    }
}

void*
DeclassifyProc(void* args) {
    try {
        WCHAR wcBuf[MAX_LINE];
        Responses response = RSP_NULL;
        TLSClientContext client;
        AuthorizationRequest ar;
        Buffer resp;
        Buffer bSelected(SelectedRemoteFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedRemoteFile);
        bSelected.NullTerminate_w();
        memset(&ar, 0, sizeof(ar));
        memcpy((void*)ar.docMAC.mls_doc_name, (wchar_t*)bSelected, bSelected.Size());

        RequestAuthorization(client, &ar, CMD_DECLASSIFY_DOCUMENT, resp, true);

        {
            ResponseHeader* prh = (ResponseHeader*)resp;
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            if (prh) {
                swprintf_s(wcBuf, MAX_LINE, L"%s %s\r\nResponse = %s(%d)\r\n",
                    (prh->response == RSP_SUCCESS) ? L"DECLASSIFIED," : L"NOT DECLASSIFIED,",
                    (wchar_t*)bSelected, wcErrorStrings[prh->response], prh->response);
                response = prh->response;
            }
            SetRemoteStatus((WCHAR*)wcBuf, true);
        }

        GetRemoteFileNames();

        return 0;
    }
    catch (...) {
        return 0;
    }
}

void*
DownloadProc(void* args) {
    try {
        bool bRequest = false;
        WCHAR wcBuf[MAX_LINE];
        Responses response = RSP_NULL;
        TLSClientContext client;
        AuthorizationRequest ar;
        Buffer bPerm;
        Buffer resp;
        Buffer bSelected(SelectedRemoteFolder);
        bSelected.Append((void*)L"\\", sizeof(WCHAR));
        bSelected.Append(SelectedRemoteFile);
        bSelected.NullTerminate_w();
        memset(&ar, 0, sizeof(ar));
        memcpy((void*)ar.docMAC.mls_doc_name, (wchar_t*)bSelected, bSelected.Size());
        if (wcsstr((wchar_t*)bSelected, L"SoftwareInstallers")) {
            bRequest = RequestAuthorization(client, &ar, CMD_DOWNLOAD_SW_INSTALLER, resp, false);
        }
        else if (wcsstr((wchar_t*)bSelected, L"Declassified")) {
            bRequest = RequestAuthorization(client, &ar, CMD_DOWNLOAD_DECLASSIFIED, resp, false);
        }
        else {
            bRequest = RequestAuthorization(client, &ar, CMD_DOWNLOAD_DOCUMENT, resp, false);
        }
        if (bRequest && (resp.Size() == sizeof(ResponseHeader))) {
            Buffer bTemp;
            ResponseHeader* prh = (ResponseHeader*)resp;
  
            if (CreateClassifiedFolders(bPerm, bTemp)) {
                std::shared_ptr<NotifyView> nv = std::make_shared<NotifyView>();
                nv->function = UpdateProgress;
                nv->hWnd = ProgressBarWidget.GetHWnd();
                bPerm.Append((void*)L"\\", sizeof(WCHAR));
                bPerm.Append((void*)SelectedRemoteFile, SelectedRemoteFile.Size());
                bPerm.NullTerminate_w();
                bTemp.Append((void*)L"\\", sizeof(WCHAR));
                bTemp.Append((void*)SelectedRemoteFile, SelectedRemoteFile.Size());
                bTemp.NullTerminate_w();

                if (prh->szData > 0)
                {
                    int max = 100;
                    int step = 1;
                    SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETRANGE, 0, MAKELPARAM(0, max));
                    SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETSTEP, (WPARAM)step, 0);
                }
                SetRemoteStatus((WCHAR*)L"Starting to download...\n", true);
                if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
                    response = DocHandler::ReceiveDocumentFromProxy(MyLocalClient->GetSock(), (wchar_t*)bPerm, (wchar_t*)bTemp, prh->szData, nv);
                }
                else {
                    response = DocHandler::ReceiveDocument(client, (wchar_t*)bPerm, (wchar_t*)bTemp, prh->szData, nv);
                }

                SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);

                {
                    memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
                    swprintf_s(wcBuf, MAX_LINE,
                        L"%s\r\n%s\r\nto\r\n%s\r\n response = %s(%d)\r\n",
                        (response == RSP_SUCCESS) ? L"Success downloading" : L"Failed to download",
                        (wchar_t*)bSelected,
                        (wchar_t*)bPerm,
                        wcErrorStrings[response],
                        response);
                    SetRemoteStatus((WCHAR*)wcBuf, true);
                    if (response == RSP_SUCCESS) {
                        BuildLocalClassifiedTree();
                    }
                }
            }
        }
        else {
            ResponseHeader* prh = (ResponseHeader*)resp;
            memset((void*)wcBuf, 0, MAX_LINE * sizeof(WCHAR));
            swprintf_s(wcBuf, MAX_LINE, L"Failed to authorize downloading of %s\r\nResponse = %s(%d)\r\n",
                (wchar_t*)bSelected, wcErrorStrings[prh->response], prh->response);
            SetRemoteStatus((WCHAR*)wcBuf, true);
        }
        
        return 0;
    }
    catch (...) {
        SendMessage(ProgressBarWidget.GetHWnd(), PBM_SETPOS, 0, 0);
        return 0;
    }
}

std::wstring GetExeFromPath(std::wstring path)
{
    std::wstring r = L"";
    wchar_t* tt = nullptr;
    wchar_t* ll = nullptr;
    tt = wcstok_s((WCHAR*)path.c_str(), L"\\", &ll);
    while (tt) {
        r = tt;
        tt = wcstok_s(0, L"\\", &ll);
    }

    return r;
}

bool
PEMcsr_to_DERcsr(
    Buffer& cert,
    uint32_t& sz)
{
    try {
        if (cert.Size() > 0) {
            char* pCert = (char*)cert;
            char* pcTmp = nullptr;
            char* pcBegin = strstr(pCert, (char*)"-----BEGIN CERTIFICATE REQUEST-----");
            char* pcEnd = strstr(pCert, (char*)"-----END CERTIFICATE REQUEST-----");

            if (!pcBegin || !pcEnd) {
                return false;
            }

            if (pcBegin >= pcEnd) {
                return false;
            }

            pcTmp = pcEnd;// strstr(pCert, (char*)"-----END CERTIFICATE REQUEST-----");
            if (pcTmp) {
                Buffer pem;
                Buffer der;
                
                pcTmp[0] = 0;
                pcTmp = pCert + strlen((char*)"-----BEGIN CERTIFICATE REQUEST-----");
                sz = (uint32_t)strlen(pcTmp);
                pem.Append(pcTmp, sz);
                if (PEM_Decode(pem, der, sz)) {
                    cert.Clear();
                    cert.Append((uint8_t*)der, sz);
                    return true;
                }
            }
        }
        return false;
    }
    catch (...) {
        cert.Clear();
        sz = 0;
        return false;
    }
}

int ShowLocalFiles()
{
    try {
        HTREEITEM Parent = 0;
        TVITEM tvitem;
        Buffer wcName;
        Buffer files;
        WCHAR temp[1024];
        WCHAR* pwcText = 0;
        HTREEITEM Selected = TreeView_GetSelection(LocalTreeWidget.GetHWnd());
        if (!Selected)
        {
            return 0;
        }

        ListView_DeleteAllItems(LocalFilesWidget.GetHWnd());
        memset(temp, 0, sizeof(temp));
        // Get the text for the item.
        tvitem.mask = TVIF_TEXT;
        tvitem.hItem = Selected;
        tvitem.pszText = temp;
        tvitem.cchTextMax = sizeof(temp) / sizeof(WCHAR) - 1;
        TreeView_GetItem(LocalTreeWidget.GetHWnd(), &tvitem);
        temp[sizeof(temp) / sizeof(WCHAR) - 1] = 0;
        wcName.Append((void*)temp, wcslen(temp) * sizeof(WCHAR));
        Parent = TreeView_GetParent(LocalTreeWidget.GetHWnd(), Selected);
        while (Parent)
        {
            memset(temp, 0, sizeof(temp));
            tvitem.hItem = Parent;
            tvitem.pszText = temp;
            tvitem.cchTextMax = sizeof(temp) / sizeof(WCHAR) - 1;
            TreeView_GetItem(LocalTreeWidget.GetHWnd(), &tvitem);
            wcName.Prepend((void*)L"\\", sizeof(WCHAR));
            wcName.Prepend((void*)temp, wcslen(temp) * sizeof(WCHAR));
            Parent = TreeView_GetParent(LocalTreeWidget.GetHWnd(), Parent);
        }
        SelectedLocalFolder = wcName;

        wcName.NullTerminate_w();
        if (GetDirectoryContents((WCHAR*)wcName, files) > 0) {
            LVITEM lvI;
            wchar_t* pc = (wchar_t*)files;
            wchar_t* tt = nullptr;
            wchar_t* ll = nullptr;
            int idx = 0;

            if (hFolderImgList)
                ImageList_Destroy(hFolderImgList);
            hFolderImgList = GetImageListForDirectoryFiles(wcName, files);
            ListView_SetImageList(LocalFilesWidget.GetHWnd(), hFolderImgList, LVSIL_NORMAL);

            tt = wcstok_s(pc, L"\n", &ll);
            while (tt) {
                Buffer c;
                wchar_t* pwcMsg = tt;
                lvI.pszText = pwcMsg; // Sends an LVN_GETDISPINFO message.
                lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_STATE;
                lvI.stateMask = 0;
                lvI.iSubItem = 0;
                lvI.state = 0;
                lvI.iItem = idx;
                lvI.iImage = idx;

                ListView_InsertItem(LocalFilesWidget.GetHWnd(), &lvI);
                tt = wcstok_s(0, L"\n", &ll);
                idx++;
            }
        }
    }
    catch (...) {
        return 0;
    }

    return 0;
}

bool CreateSandboxScript(Buffer& bScriptName)
{
    try {
        Buffer bScript;
        size_t requiredSize = 0;
        char szExeFileName[MAX_NAME];
        GetModuleFileNameA(NULL, szExeFileName, MAX_NAME);

        if (!GetSandboxScript(bScript)) {
            return false;
        }

        getenv_s(&requiredSize, 0, 0, "USERPROFILE");
        if (requiredSize > 0)
        {
            Buffer bEnv(requiredSize + 1);
            getenv_s(&requiredSize, (char*)bEnv, requiredSize, "USERPROFILE");
            //FIXME
            {
                Buffer bTmp;
                bTmp.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
                bTmp.Append((void*)"\\Documents\\Temp", strlen("\\Documents\\Temp"));
                bTmp.NullTerminate();
                if (!CreateDirectoryA((char*)bTmp, 0)) {
                    if (GetLastError() != ERROR_ALREADY_EXISTS) {
                        return false;
                    }
                }
            }

            {
                NdacClientConfig& conf = NdacClientConfig::GetInstance();
                Buffer bTmp;
                Buffer bCAFile = conf.GetValue(TRUSTED_CA_FILE);
                bTmp.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
                bTmp.Append((void*)"\\Documents\\Temp", strlen("\\Documents\\Temp"));
                bTmp.Append((void*)"\\CAFile.crt", strlen("\\CAFile.crt"));
                bTmp.NullTerminate();
                CopyFileA((char*)bCAFile, (char*)bTmp, FALSE);
            }

            {
                FILE* fp = nullptr;
                Buffer bBatch;
                bBatch.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
                bBatch.Append((void*)"\\Documents\\Temp", strlen("\\Documents\\Temp"));
                bBatch.Append((void*)"\\acstartup.cmd", strlen("\\acstartup.cmd"));
                bBatch.NullTerminate();
                fp = f_open_f((char*)bBatch, (char*)"wb");
                if (fp) {
                    char l1[] = "auditpol.exe /set /category:\"Policy Change\" /subcategory:\"MPSSVC rule-level Policy Change\" /success:enable /failure:enable\n";
                    char l2[] = "C:\\users\\WDAGUtilityAccount\\Downloads\\AuthClient.exe /SandBoxedAuth ";
                    char l3[] = "\n";
                    fwrite((void*)l1, strlen(l1), 1, fp);
                    fwrite((void*)l2, strlen(l2), 1, fp);
                    {
                        uint8_t nonce[16];
                        RAND_bytes(nonce, sizeof(nonce));
                        hexEncode(nonce, sizeof(nonce), SandBoxAuthBuf);
                        SandBoxAuthBuf.NullTerminate();
                        fwrite((void*)SandBoxAuthBuf, SandBoxAuthBuf.Size(), 1, fp);
                        fwrite((void*)l3, strlen(l3), 1, fp);
                    }
                    fclose(fp);
                }
            }

            {
                Buffer bExe;
                bExe.Append((void*)bEnv, wcslen((WCHAR*)bEnv) * sizeof(WCHAR));
                bExe.Append((void*)"\\Documents\\Temp", strlen("\\Documents\\Temp"));
                bExe.Append((void*)"\\AuthClient.exe", strlen("\\AuthClient.exe"));
                bExe.NullTerminate();
                CopyFileA(szExeFileName, (char*)bExe, FALSE);

                bScriptName.Append((void*)bEnv, strlen((char*)bEnv));
                bScriptName.Append((void*)"\\Documents\\Temp\\", strlen("\\Documents\\Temp\\"));
                bScriptName.Append((void*)SandBoxAuthBuf, strlen((char*)SandBoxAuthBuf));
                bScriptName.Append((void*)".wsb", strlen(".wsb"));
                bScriptName.NullTerminate();
                {
                    FILE* fp = f_open_f((char*)bScriptName, (char*)"wb");
                    if (fp) {
                        uint32_t sz = bScript.Size() * 2;
                        Buffer b(sz);
                        StringCbPrintfA((char*)b, sz, (char*)bScript, (char*)bEnv);
                        fwrite((void*)b, strlen((char*)b), 1, fp);
                        fclose(fp);
                    }
                }
            }

        }
    }
    catch (...) {
        bScriptName.Clear();
        return false;
    }

    return true;
}

void* LaunchSandbox(void* args)
{
    try {
        int max = 0;
        SHELLEXECUTEINFOA ShExecInfo;
        Buffer bScriptName;

        if (!CreateSandboxScript(bScriptName)) {
            MessageBoxA(NULL, (char*)"Failed to retrieve sandbox script!", (char*)"Error", MB_OK);
            return 0;
        }

        ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
        ShExecInfo.fMask = NULL;
        ShExecInfo.hwnd = NULL;
        ShExecInfo.lpVerb = NULL;
        ShExecInfo.lpFile = (char*)bScriptName;
        ShExecInfo.lpParameters = NULL;
        ShExecInfo.lpDirectory = NULL;
        ShExecInfo.nShow = SW_MAXIMIZE;
        ShExecInfo.hInstApp = NULL;
        ShellExecuteExA(&ShExecInfo);

        do {
            max++;
            std::this_thread::yield();
        } while (!IsWinSandboxRunning() && (max < 100));

        DeleteFileA((char*)bScriptName);

        return 0;
    }
    catch (...) {
        return 0;
    }
}

int Connect()
{
    if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
        if (AuthenticateToProxy() && GetUserCertFromProxy()) {
            return GetRemoteDocumentTree();
        }
        return -1;
    }
    else if (SandBoxedState == NdacClientConfig::SandboxedState::OUTSIDE) {
        if (IsWinSandboxRunning()) {
            MessageBoxA(NULL, (char*)"Windows Sandbox is already running!\nStop it first!", (char*)"Connect", MB_OK);
            return -1;
        }
        else if (SandboxSocket) {
            MessageBoxA(NULL, (char*)"Previous Windows Sandbox was improperly terminated!\nPlease restart the client app!", (char*)"Connect", MB_OK);
            return -1;
        }
        else if (ClientChooseUserKey()) {
            MessageBoxA(NULL, (char*)"Sandbox Proxy Started", (char*)"Sandbox", MB_OK);
            BuildLocalClassifiedTree();
            threadPool::queueThread((void*)OutOfBoxServer, 0);
            //Running = TRUE;
            threadPool::queueThread((void*)LaunchSandbox, 0);
            return 0;
        }
    }
    else {
        if (ClientChooseUserKey()) {
            return GetRemoteDocumentTree();
        }
    }
    return 0;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int				wmId, wmEvent;
    PAINTSTRUCT		ps;
    HDC				hdc;
    int				left = 0;
    int				width = 0;
    int				top = 0;
    int				height = 0;
    RECT			rect;
    HFONT			hOldFont = NULL;

    time(&appStart);

    hWaitCursor = LoadCursor(NULL, IDC_WAIT);

    GetClientRect(hWnd, &rect);
    hAppWnd = hWnd;

    switch (message)
    {
    case WM_CLOSE:
        if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
            MySystemShutdown();
        }
        else if (IsWinSandboxRunning()) {
            TerminateSandbox();
        }
        DestroyWindow(hWnd);
        break;
    case WM_MOUSEMOVE:
        mouseMoves++;
        break;
    case WM_CREATE:
    {
        size_t i;
        CreateToolTip();

        hAppFont = CreateFont(16, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, ANSI_CHARSET,
            OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, TEXT("Arial"));

        hSmallFont = CreateFont(10, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, ANSI_CHARSET,
            OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, TEXT("Arial"));

        MainWinWidget.SetAsRoot(hAppWnd);
        MainWinWidget.AddLeftTopAnchorWidget(GetPlacementFor(&ToolBarWidget)->widthPercent,
                                             GetPlacementFor(&ToolBarWidget)->heightPercent, ToolBarWidget);
        ToolBarWidget.CreateView(0, (TCHAR*)L"STATIC", (TCHAR*)L"", WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);

        ToolBarWidget.AddRightTopAnchorWidget(GetPlacementFor(&UserPrincipalWidget)->widthPercent,
                                              GetPlacementFor(&UserPrincipalWidget)->heightPercent, UserPrincipalWidget);
        UserPrincipalWidget.CreateView(0, (TCHAR*)L"STATIC", (TCHAR*)L" Authenticated as:",
            WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);
        SetWindowPos(UserPrincipalWidget.GetHWnd(), ToolBarWidget.GetHWnd(), 0, 0, 0, 0, SWP_SHOWWINDOW);

        //start tooltip buttons
        ToolBarWidget.AddLeftTopAnchorWidget(BUTTON_WIDTH, BUTTON_HEIGHT, ButtonWidget[0]);
        for (i = 1; i < NUM_TOOLBAR_BUTTONS; i++)
        {
            ButtonWidget[i - 1].AddSiblingWidgetToRight(BUTTON_WIDTH, BUTTON_HEIGHT, ButtonWidget[i]);
        }

        for (i = 0; i < NUM_TOOLBAR_BUTTONS; i++)
        {
            size_t x = min((int)numIcons - 1, hwndIconIndices[i]);

            ButtonWidget[i].CreateView(0, (TCHAR*)L"BUTTON", NULL,
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | BS_ICON, NULL, NULL, hAppFont, wcEnglishTooltips[i], hWnd, hwndTT);

            SetWindowLongPtr(ButtonWidget[i].GetHWnd(), GWLP_ID, static_cast<LONG_PTR>(static_cast<DWORD_PTR>(IDC_NO_OP + i + 1)));
            SendMessage(ButtonWidget[i].GetHWnd(), WM_SETFONT, (WPARAM)hAppFont, TRUE);
            SendMessage(ButtonWidget[i].GetHWnd(), (UINT)BM_SETIMAGE, (WPARAM)IMAGE_ICON, (LPARAM)hSmallIcons[x]);
            SetWindowPos(ButtonWidget[i].GetHWnd(), ToolBarWidget.GetHWnd(), 0, 0, 0, 0, SWP_SHOWWINDOW);
        }

        UserPrincipalWidget.AddSiblingWidgetToLeft(GetPlacementFor(&ProgressBarWidget)->widthPercent,
                                                   GetPlacementFor(&ProgressBarWidget)->heightPercent, ProgressBarWidget);
        ProgressBarWidget.CreateView(0, (TCHAR*)PROGRESS_CLASS, NULL,
            WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, (WCHAR*)L"Operation progress", NULL, hwndTT);
        SetWindowPos(ProgressBarWidget.GetHWnd(), ToolBarWidget.GetHWnd(), 0, 0, 0, 0, SWP_SHOWWINDOW);

        ProgressBarWidget.AddSiblingWidgetToLeft(GetPlacementFor(&ProgressTextWidget)->widthPercent,
            GetPlacementFor(&ProgressTextWidget)->heightPercent, ProgressTextWidget);
        ProgressTextWidget.CreateView(0, (TCHAR*)L"STATIC", NULL, WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);

        //**********************
        //end tooltip buttons
        ToolBarWidget.AddSiblingWidgetBelow(GetPlacementFor(&AppsViewWidget)->widthPercent,
                                            GetPlacementFor(&AppsViewWidget)->heightPercent, AppsViewWidget);

        AppsViewWidget.AddSiblingWidgetBelow(GetPlacementFor(&RemoteDirTitleWidget)->widthPercent,
                                             GetPlacementFor(&RemoteDirTitleWidget)->heightPercent, RemoteDirTitleWidget);

        RemoteDirTitleWidget.AddSiblingWidgetToRight(GetPlacementFor(&RemoteFilesTitleWidget)->widthPercent,
                                                     GetPlacementFor(&RemoteFilesTitleWidget)->heightPercent, RemoteFilesTitleWidget);

        RemoteFilesTitleWidget.AddSiblingWidgetToRight(GetPlacementFor(&LocalDirTitleWidget)->widthPercent,
                                                       GetPlacementFor(&LocalDirTitleWidget)->heightPercent, LocalDirTitleWidget);

        LocalDirTitleWidget.AddSiblingWidgetToRight(GetPlacementFor(&LocalFilesTitleWidget)->widthPercent,
                                                    GetPlacementFor(&LocalFilesTitleWidget)->heightPercent, LocalFilesTitleWidget);

        AppsViewWidget.CreateView(0, (TCHAR*)WC_LISTVIEW, (TCHAR*)L"List View",
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | WS_HSCROLL,
            (HMENU)IDC_APPLICATIONS_LIST, hInst, hSmallFont, NULL, hWnd, hwndTT);

        RemoteDirTitleWidget.CreateView(0, (TCHAR*)L"STATIC", (TCHAR*)L"Remote Directory",
            WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);
        SetWindowPos(RemoteDirTitleWidget.GetHWnd(), HWND_TOP, 0, 0, 0, 0, SWP_SHOWWINDOW);

        RemoteFilesTitleWidget.CreateView(0, (TCHAR*)L"STATIC", (TCHAR*)L"Remote Files",
            WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);
        SetWindowPos(RemoteFilesTitleWidget.GetHWnd(), HWND_TOP, 0, 0, 0, 0, SWP_SHOWWINDOW);

        LocalDirTitleWidget.CreateView(0, (TCHAR*)L"STATIC", (TCHAR*)L"Local Directory",
            WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);
        SetWindowPos(LocalDirTitleWidget.GetHWnd(), HWND_TOP, 0, 0, 0, 0, SWP_SHOWWINDOW);

        LocalFilesTitleWidget.CreateView(0, (TCHAR*)L"STATIC", (TCHAR*)L"Local Files",
            WS_CHILD | WS_VISIBLE, NULL, NULL, hAppFont, NULL, NULL, hwndTT);
        SetWindowPos(LocalFilesTitleWidget.GetHWnd(), HWND_TOP, 0, 0, 0, 0, SWP_SHOWWINDOW);

        RemoteDirTitleWidget.AddSiblingWidgetBelow(GetPlacementFor(&RemoteTreeWidget)->widthPercent,
                                                   GetPlacementFor(&RemoteTreeWidget)->heightPercent, RemoteTreeWidget);
        RemoteTreeWidget.CreateView(0, (TCHAR*)WC_TREEVIEW, (TCHAR*)L"Tree View",
            WS_VISIBLE | WS_CHILD | WS_BORDER | TVS_HASLINES | WS_VSCROLL | WS_HSCROLL | TVS_HASBUTTONS,
            (HMENU)IDC_LV_MLS, hInst, hAppFont, NULL, hWnd, hwndTT);
        TreeView_SetImageList(RemoteTreeWidget.GetHWnd(), hShellImages, TVSIL_NORMAL);

        RemoteTreeWidget.AddSiblingWidgetToRight(GetPlacementFor(&RemoteFilesWidget)->widthPercent,
                                                 GetPlacementFor(&RemoteFilesWidget)->heightPercent, RemoteFilesWidget);
        RemoteFilesWidget.CreateView(0, (TCHAR*)WC_LISTVIEW, (TCHAR*)L"List View",
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | WS_HSCROLL,
            (HMENU)IDC_REMOTE_FILES_LIST, hInst, hAppFont, NULL, hWnd, hwndTT);
        ListView_SetImageList(RemoteFilesWidget.GetHWnd(), hAppImages, LVSIL_NORMAL);

        RemoteFilesWidget.AddSiblingWidgetToRight(GetPlacementFor(&LocalTreeWidget)->widthPercent,
                                                  GetPlacementFor(&LocalTreeWidget)->heightPercent, LocalTreeWidget);
        LocalTreeWidget.CreateView(0, (TCHAR*)WC_TREEVIEW, (TCHAR*)L"Tree View",
            WS_VISIBLE | WS_CHILD | WS_BORDER | TVS_HASLINES | WS_VSCROLL | WS_HSCROLL | TVS_HASBUTTONS,
            (HMENU)IDC_LV_LOCAL_MLS, hInst, hAppFont, NULL, hWnd, hwndTT);
        TreeView_SetImageList(LocalTreeWidget.GetHWnd(), hShellImages, TVSIL_NORMAL);

        LocalTreeWidget.AddSiblingWidgetToRight(GetPlacementFor(&LocalFilesWidget)->widthPercent,
                                                GetPlacementFor(&LocalFilesWidget)->heightPercent, LocalFilesWidget);
        LocalFilesWidget.CreateView(0, (TCHAR*)WC_LISTVIEW, (TCHAR*)L"List View",
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | WS_HSCROLL,
            (HMENU)IDC_LOCAL_FILES_LIST, hInst, hAppFont, NULL, hWnd, hwndTT);

        RemoteTreeWidget.AddSiblingWidgetBelow(GetPlacementFor(&RemoteStatusWidget)->widthPercent,
                                               GetPlacementFor(&RemoteStatusWidget)->heightPercent, RemoteStatusWidget);
        RemoteStatusWidget.CreateView(0, (TCHAR*)L"RICHEDIT50W", (TCHAR*)L"Remote status messages",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_BORDER | ES_READONLY | WS_VSCROLL,
            NULL, hInst, hAppFont, NULL, hWnd, hwndTT);

        LocalTreeWidget.AddSiblingWidgetBelow(GetPlacementFor(&LocalStatusWidget)->widthPercent,
                                              GetPlacementFor(&LocalStatusWidget)->heightPercent, LocalStatusWidget);
        LocalStatusWidget.CreateView(0, (TCHAR*)L"RICHEDIT50W", (TCHAR*)L"Local status messages",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_BORDER | ES_READONLY | WS_VSCROLL,
            NULL, hInst, hAppFont, NULL, hWnd, hwndTT);

        //Admin can only configure the client. Cannot use it.
        //Config button is the last on the toolbar
        for (i = 0; i < NUM_TOOLBAR_BUTTONS; i++)
        {
            if (IsAdmin()) {
                EnableWindow(ButtonWidget[i].GetHWnd(), (i == ((NUM_TOOLBAR_BUTTONS - 1))));
            }
            else {
                EnableWindow(ButtonWidget[i].GetHWnd(), (i < ((NUM_TOOLBAR_BUTTONS - 1))));
            }
#ifdef _DEBUG
            EnableWindow(ButtonWidget[i].GetHWnd(),TRUE);
#endif
        }

        //Inside the sandbox, only the connect is enabled
        if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
            for (i = 0; i < NUM_TOOLBAR_BUTTONS; i++)
            {
                EnableWindow(ButtonWidget[i].GetHWnd(), (i == 0));
            }
        }
        else if (!IsAdmin()) {
            //threadPool::queueThread((void*)StartupChecks, 0);
            StartupChecks(0);
        }
    }
    break;
    case WM_SIZE:
    {
        UIready = TRUE;
        //move widgets in the order they were created
        MainWinWidget.MoveView(true);
        Widget::MoveWidgets(true);
    }
    break;
    case WM_COMMAND:
        wmId = LOWORD(wParam);
        wmEvent = HIWORD(wParam);
        // Parse the menu selections:
        switch (wmId)
        {
        case IDC_ABOUT:
        {
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        }
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        case IDC_CONNECT_AUTH_HOST:
            try {
                if (UpProgress()) {
                    Connect();//BuildTestTree();
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_CREATE_CSR:
            try {
                CLdap ldap;
                Buffer attrs;
                DWORD   len = 0;
                NdacClientConfig& ccfg = NdacClientConfig::GetInstance();
                attrs.Append((void*)LDAP_SEPS, strlen(LDAP_SEPS));
                attrs.EOLN();
                GetUserNameExA(NameUserPrincipal, nullptr, &len);
                if (len > 0) {
                    Buffer bUPN((size_t)len + 1);
                    GetUserNameExA(NameUserPrincipal, (char*)bUPN, &len);
                    if (ldap.Connect()) {
                        if (ldap.Bind()) {
                            Buffer bTmpUPN;
                            bTmpUPN.Append((void*)bUPN, len);
                            bTmpUPN.NullTerminate();
                            ldap.GetAttributes(bTmpUPN, attrs);
                        }
                    }

                    DoSCardDialog(hInst, hWnd, attrs);
                }
#ifdef _DEBUG
                else {
                    DoSCardDialog(hInst, hWnd, attrs);
                }
#endif
                break;
            }
            catch (...) {
                break;
            }
        case IDC_MANAGE_PRIVATE_KEYS:
            ClientChooseUserKey();
            break;
        case IDC_ADD_CERT_TO_CARD:
            try {
                bool bAdd = false;
                Buffer bCert;
                Buffer bUPN;
                DWORD len = 0;
                GetUserNameEx(NameUserPrincipal, nullptr, &len);
                if (len > 0) {
                    Buffer b(len * sizeof(WCHAR));
                    GetUserNameEx(NameUserPrincipal, (WCHAR*)b, &len);
                    bUPN.Append((void*)b, len * sizeof(WCHAR));
                    bUPN.NullTerminate_w();
                }
                else {
#ifdef _DEBUG
                    WCHAR c[] = L"aadean@reiazdean.ca";
                    bUPN.Clear();
                    bUPN.Append((void*)c, wcslen(c) * sizeof(WCHAR));
                    bUPN.NullTerminate_w();
#else
                    SetLocalStatus((WCHAR*)L"Failed to add certificate to smartcard! Cannot determine UPN.", true);
                    break;
#endif
                }

                DoAddCertToSCardDialog(hInst, hWnd, bUPN);

                break;
            }
            catch (...) {
                break;
            }
        case IDC_ABOUT_ME:
            try {
                if (MyChosenKey.Size() > 0) {
                    if (UpProgress()) {
                        AboutMe(0);
                        DownProgress();
                    }
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_CONFIG:
            try {
                if (SandBoxedState != NdacClientConfig::SandboxedState::INSIDE) {
                    DoConfigDialog(hInst, hWnd);
                }
                break;
            }
            catch (...) {
                break;
            }
        case ID_UPLOAD_FILE:
            try {
                if (UpProgress()) {
                    UploadProc(0);
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case ID_ENCRYPT_FILE:
            try {
                if (UpProgress()) {
                    EncryptProc(0);//threadPool::queueThread((void*)EncryptProc, 0);//
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case ID_DECRYPT_FILE:
            try {
                if (UpProgress()) {
                    DecryptProc(0);//threadPool::queueThread((void*)DecryptProc, 0);//
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case ID_VERIFY_FILE:
            try {
                if (UpProgress()) {
                    VerifyProc(0);// threadPool::queueThread((void*)VerifyProc, 0);
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case ID_OPEN_FILE:
            try {
                threadPool::queueThread((void*)OpenSelectedProc, 0);
                break;
            }
            catch (...) {
                break;
            }
        case ID_DOWNLOAD_FILE:
            try {
                if (UpProgress()) {
                    DownloadProc(0);
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case ID_PUBLISH_FILE:
            try {
                if (UpProgress()) {
                    PublishProc(0);
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_DECLASSIFY_FILE:
            try {
                if (UpProgress()) {
                    DeclassifyProc(0);
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case ID_REMOTE_VERIFY_FILE:
            try {
                if (UpProgress()) {
                    RemoteVerifyProc(0);
                    DownProgress();
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    case WM_NOTIFY:
        wmId = LOWORD(wParam);
        wmEvent = HIWORD(wParam);
        // Parse the menu selections:
        switch (wmId)
        {
        case IDC_APPLICATIONS_LIST:
            try {
                if (((LPNMHDR)lParam)->code == NM_CLICK)
                {
                    int item = ListView_GetNextItem(AppsViewWidget.GetHWnd(), -1, LVNI_SELECTED);
                    if (item >= 0) {
                        Buffer bTemp(MAX_NAME * sizeof(WCHAR));
                        ListView_GetItemText(AppsViewWidget.GetHWnd(), item, 0, (WCHAR*)bTemp, MAX_NAME - 1);
                        std::wstring ws = GetMappedValue((WCHAR*)bTemp);
                        Launch((WCHAR*)ws.c_str());
                    }
                    /*if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
                        keybd_event(VK_LWIN, 0, 0, 0);
                        keybd_event(VK_LWIN, 0, KEYEVENTF_KEYUP, 0);
                    }*/
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_REMOTE_FILES_LIST:
            try {
                if (((LPNMHDR)lParam)->code == NM_RCLICK)
                {
                    POINT		pt;
                    HMENU		hPopupMenu;
                    int item = ListView_GetNextItem(RemoteFilesWidget.GetHWnd(), -1, LVNI_SELECTED);
                    if (item >= 0) {
                        Buffer bTemp(MAX_NAME * sizeof(WCHAR));
                        ListView_GetItemText(RemoteFilesWidget.GetHWnd(), item, 0, (WCHAR*)bTemp, MAX_NAME - 1);
                        SelectedRemoteFile = Buffer((void*)bTemp, wcslen(bTemp) * sizeof(WCHAR));
                        //popup menu
                        GetCursorPos(&pt);
                        hPopupMenu = CreatePopupMenu();
                        if (!OperationInProgress) {
                            if ((SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) ||
                                (SandBoxedState == NdacClientConfig::SandboxedState::NONE)) {
                                if (wcsstr((WCHAR*)SelectedRemoteFolder, L"Drafts")) {
                                    if (wcsstr((WCHAR*)SelectedRemoteFile, L".classified")) {
                                        if (!wcsstr((WCHAR*)SelectedRemoteFile, L".published") &&
                                            !wcsstr((WCHAR*)SelectedRemoteFile, L".declassified")) {
                                            InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_DOWNLOAD_FILE, L"Downlaod");
                                            InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_PUBLISH_FILE, L"Publish");
                                            InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_REMOTE_VERIFY_FILE, L"Verify");
                                            InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, IDC_DECLASSIFY_FILE, L"Declassify");
                                        }
                                    }
                                }
                                else if (wcsstr((WCHAR*)SelectedRemoteFolder, L"Published")) {
                                    if (wcsstr((WCHAR*)SelectedRemoteFile, L".classified") &&
                                        !wcsstr((WCHAR*)SelectedRemoteFile, L".declassified")) {
                                        InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_DOWNLOAD_FILE, L"Downlaod");
                                        InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_REMOTE_VERIFY_FILE, L"Verify");
                                        InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, IDC_DECLASSIFY_FILE, L"Declassify");
                                    }
                                }
                                else if (wcsstr((WCHAR*)SelectedRemoteFolder, L"Declassified")) {
                                    if (!wcsstr((WCHAR*)SelectedRemoteFile, L".classified")) {
                                        InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_DOWNLOAD_FILE, L"Downlaod");
                                    }
                                }
                                else if (wcsstr((WCHAR*)SelectedRemoteFolder, L"SoftwareInstallers")) {
                                    InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_DOWNLOAD_FILE, L"Downlaod");
                                }
                                
                            }
                        }
                        SetForegroundWindow(hWnd);
                        TrackPopupMenu(hPopupMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
                    }
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_LOCAL_FILES_LIST:
            try {
                if (((LPNMHDR)lParam)->code == NM_RCLICK)
                {
                    POINT		pt;
                    HMENU		hPopupMenu;
                    int item = ListView_GetNextItem(LocalFilesWidget.GetHWnd(), -1, LVNI_SELECTED);
                    if (item >= 0) {
                        Buffer bTemp(MAX_NAME * sizeof(WCHAR));
                        ListView_GetItemText(LocalFilesWidget.GetHWnd(), item, 0, (WCHAR*)bTemp, MAX_NAME - 1);
                        SelectedLocalFile = Buffer((void*)bTemp, wcslen(bTemp) * sizeof(WCHAR));
                        //popup menu
                        GetCursorPos(&pt);
                        hPopupMenu = CreatePopupMenu();
                        if (wcsstr((WCHAR*)bTemp, L".classified")) {
                            if (!OperationInProgress) {
                                InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_DECRYPT_FILE, L"Decrypt");
                                InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_VERIFY_FILE, L"Verify");
                                if (wcsstr((WCHAR*)SelectedLocalFolder, L"Drafts")) {
                                    InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_UPLOAD_FILE, L"Upload");
                                }
                            }
                        }
                        else
                        {
                            if (!OperationInProgress) {
                                InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_OPEN_FILE, L"Open");
                                if (!wcsstr((WCHAR*)SelectedLocalFolder, L"Declassified")) {
                                    InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_ENCRYPT_FILE, L"Encrypt");
                                }
                            }
                        }
                        SetForegroundWindow(hWnd);
                        TrackPopupMenu(hPopupMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
                    }
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_LV_MLS:
            try {
                if (((LPNMHDR)lParam)->code == NM_DBLCLK)
                {
                    if (UpProgress()) {
                        GetRemoteFileNames();
                        DownProgress();
                    }
                }
                else if (((LPNMHDR)lParam)->code == NM_RCLICK)
                {
                    break;
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        case IDC_LV_LOCAL_MLS:
            try {
                if (((LPNMHDR)lParam)->code == NM_DBLCLK)
                {
                    if (UpProgress()) {
                        ShowLocalFiles();
                        DownProgress();
                    }
                }
                else if (((LPNMHDR)lParam)->code == NM_RCLICK)
                {
                    break;
                }
                break;
            }
            catch (...) {
                DownProgress();
                break;
            }
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    case WM_PAINT:
        hdc = BeginPaint(hWnd, &ps);
        if ((rect.bottom < 200) || (rect.right < 300))
        {
            EndPaint(hWnd, &ps);
            break;
        }
        // TODO: Add any drawing code here...
        hOldFont = SelectFont(hdc, hAppFont);

        rect.top = TOP_INSET;
        rect.left = 5;

        if (hOldFont)
            SelectFont(hdc, hOldFont);

        EndPaint(hWnd, &ps);
        break;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
        hdc = (HDC)wParam;
        SetTextColor(hdc, colorBlue);
        return (INT_PTR)hWindowBrush;
    case WM_CTLCOLORBTN:
        hdc = (HDC)wParam;
        SetTextColor(hdc, colorBlue);
        return (INT_PTR)hButtonBrush;
    case WM_CTLCOLORSTATIC:
    {
        HDC hDC = (HDC)wParam;
        SetTextColor(hDC, RGB(0, 0, 0));
        SetBkMode(hDC, TRANSPARENT);
        return (INT_PTR)h3DlightBrush;
    }
    case WM_DESTROY:
        ListView_DeleteAllItems(RemoteFilesWidget.GetHWnd());
        DeleteAllUnprotectedFiles();
        PostQuitMessage(0);
        ApplicationStopped = TRUE;
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

BOOL CALLBACK EnumChildProc(HWND hwndChild, LPARAM lParam)
{
    return TRUE;
}
