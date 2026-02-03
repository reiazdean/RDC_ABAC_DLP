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
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <shellapi.h>
#include <iostream>
#include <commctrl.h>
#include <stdio.h>
#include <Windowsx.h>
#include <msi.h>
#include <ncrypt.h>
#include "threadPool.h"
#include "KSPkey.h"

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/ms644996(v=vs.85).aspx#modal_box
*/

enum IDS {
    ID_SC_PK_STATIC1 = 500,
    ID_SC_PK_STATIC2,
    ID_SC_PK_STATIC3,
    ID_SC_PRIV_KEY_LB1,
    ID_SC_PRIV_KEY_LB2,
    ID_SC_PRIV_KEY_LB3,
    ID_SC_PK_NULL
};

extern HFONT hAppFont;
extern COLORREF colorRed;
extern COLORREF colorGreen;
extern COLORREF colorBlue;


#define SC_PRIV_KEY_DLG_WIDTH 400
#define SC_PRIV_KEY_DLG_HEIGHT 230
#define SC_PRIV_KEY_MAX_TEXT 128
#define SC_PRIV_KEY_NUM_CONTROLS 8
#define SC_PRIV_KEY_NUM_STRINGS SC_PRIV_KEY_NUM_CONTROLS+1
#define SC_PRIV_KEY_STRING_SZ 128

#define SC_PRIV_KEY_BUF_SZ SC_PRIV_KEY_NUM_CONTROLS*1024

static BOOL Working = FALSE;
static HWND hThisDlg = 0;
static WPARAM wEndParam = 0;
static Buffer* pChosen = nullptr;
static WCHAR KspProv[] = L"Microsoft Smart Card Key Storage Provider";
//static WCHAR KspProv[] = L"Microsoft Software Key Storage Provider";

char cInstalledSCPKcertStrings[SC_PRIV_KEY_NUM_STRINGS][SC_PRIV_KEY_STRING_SZ] = {
    "Private Keys",
    "Name",
    "Algorithm",
    "Certificate",
    "",
    "",
    "",
    "View Certificate",
    "Choose This Key"
};

void AddCertProperty(HWND hWnd, KSPkey& ksp)
{
    Buffer bProp;
    if (ERROR_SUCCESS == ksp.GetProperty((WCHAR*)NCRYPT_CERTIFICATE_PROPERTY, bProp)) {
        ListBox_AddString(hWnd, (WCHAR*)L"Exists");
    }
    else {
        ListBox_AddString(hWnd, (WCHAR*)L"None");
    }
}

void AddAlgProperty(HWND hWnd, KSPkey& ksp)
{
    WCHAR wcOut[256];
    Buffer bAlg;
    DWORD dwLen = 0;

    if (ERROR_SUCCESS == ksp.GetProperty((WCHAR*)NCRYPT_ALGORITHM_PROPERTY, bAlg)) {
        bAlg.NullTerminate_w();
        dwLen = ksp.GetLength();
        _snwprintf_s(wcOut, 256, 256, L"%s %u", (WCHAR*)bAlg, dwLen);
        ListBox_AddString(hWnd, (WCHAR*)wcOut);
    }
    else {
        ListBox_AddString(hWnd, (WCHAR*)L"None");
    }
}

void AddKeyNames(HWND hDlg)
{
    Buffer bKeyNames;
    std::vector<WCHAR*> pieces;
    uint32_t count = 0;
    uint32_t i = 0;
    HWND hWnd = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB1);

    KSPkey::EnumKeys((WCHAR*)KspProv, bKeyNames);
    try {
        count = splitStringW((WCHAR*)bKeyNames, (WCHAR*)L"\n", pieces);
    }
    catch (...) {
        return;
    }
    
    for (i = 0; i < count; i++) {
        SECURITY_STATUS ss = NTE_FAIL;
        KSPkey ksp((WCHAR*)KspProv);
        ss = ksp.OpenKey((WCHAR*)pieces.at(i), 0);
        if (ERROR_SUCCESS == ss) {
            ListBox_AddString(hWnd, (WCHAR*)pieces.at(i));
            HWND hWnd2 = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB2);
            AddAlgProperty(hWnd2, ksp);
            hWnd2 = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB3);
            AddCertProperty(hWnd2, ksp);
        }
    }

    return;
}

void ViewCertificate(WCHAR* pwcKeyName)
{
    Buffer bCert;
    SECURITY_STATUS ss = NTE_FAIL;
    KSPkey ksp((WCHAR*)KspProv);
    HCURSOR hWaitCursor = LoadCursor(NULL, IDC_WAIT);
    HCURSOR hOldCursor = SetCursor(hWaitCursor);
    size_t requiredSize = 0;
    Buffer bFile;

    getenv_s(&requiredSize, 0, 0, "APPDATA");
    if (requiredSize > 0)
    {
        Buffer bEnv(requiredSize);
        getenv_s(&requiredSize, (char*)bEnv, requiredSize, "APPDATA");
        bFile.Append((void*)bEnv, requiredSize - 1);
        bFile.Append((char*)"\\tempXX.cer", strlen((char*)"\\tempXX.cer"));
        bFile.NullTerminate();
    }

    if (ERROR_SUCCESS == ksp.OpenKey(pwcKeyName, 0)) {
        if (ERROR_SUCCESS == ksp.GetProperty((WCHAR*)NCRYPT_CERTIFICATE_PROPERTY, bCert)) {
            saveToFile((int8_t*)bFile, (int8_t*)bCert, bCert.Size());
            SHELLEXECUTEINFOA ShExecInfo;

            ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
            ShExecInfo.fMask = NULL;
            ShExecInfo.hwnd = NULL;
            ShExecInfo.lpVerb = NULL;
            ShExecInfo.lpFile = (char*)bFile;
            ShExecInfo.lpParameters = NULL;
            ShExecInfo.lpDirectory = NULL;
            ShExecInfo.nShow = SW_NORMAL;
            ShExecInfo.hInstApp = NULL;
            SetCursor(hOldCursor);
            ShellExecuteExA(&ShExecInfo);
            return;
        }
    }

    SetCursor(hOldCursor);
    MessageBox(NULL, L"The smartcard does not contain a certificate for this private key!", pwcKeyName, MB_OK);

    return;
}

LRESULT CALLBACK ManageSCARDkeysProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    HWND hWnd;
    int sel = -1;
    WCHAR wcBuf[512];

    hThisDlg = hDlg;

    switch (message)
    {
    case WM_INITDIALOG:
    {
        Working = FALSE;

        for (int i = ID_SC_PK_STATIC1; i < ID_SC_PK_NULL; i++) {
            hWnd = GetDlgItem(hDlg, i);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
        }

        AddKeyNames(hThisDlg);

        hWnd = GetDlgItem(hDlg, IDOK);
        SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
        hWnd = GetDlgItem(hDlg, IDCANCEL);
        SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);

        return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    {
        HDC hDC = (HDC)wParam;
        SetTextColor(hDC, colorBlue);
        SetBkMode(hDC, TRANSPARENT);
        return (INT_PTR)CreateSolidBrush(GetSysColor(COLOR_WINDOW));
    }
    case WM_CTLCOLORSTATIC:
    {
        HDC hDC = (HDC)wParam;
        SetTextColor(hDC, RGB(255 * 0, 0, 255 * 0));
        SetBkMode(hDC, TRANSPARENT);
        return (INT_PTR)CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
            hWnd = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB1);
            sel = ListBox_GetCurSel(hWnd);
            if (sel >= 0) {
                memset(wcBuf, 0, sizeof(wcBuf));
                ListBox_GetText(hWnd, sel, wcBuf);
                wcBuf[(sizeof(wcBuf) / sizeof(WCHAR)) - 1] = 0;
                ViewCertificate(wcBuf);
            }
            return TRUE;
            break;
        case IDCANCEL:
            hWnd = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB1);
            sel = ListBox_GetCurSel(hWnd);
            if (pChosen && (sel >= 0)) {
                memset(wcBuf, 0, sizeof(wcBuf));
                ListBox_GetText(hWnd, sel, wcBuf);
                wcBuf[(sizeof(wcBuf) / sizeof(WCHAR)) - 1] = 0;
                pChosen->Clear();
                pChosen->Append((void*)wcBuf, wcslen(wcBuf) * sizeof(WCHAR));
                pChosen->NullTerminate_w();
            }
            EndDialog(hDlg, LOWORD(wParam));
            break;
        case ID_SC_PRIV_KEY_LB1:
            sel = -1;
            hWnd = GetDlgItem(hDlg, LOWORD(wParam));
            sel = ListBox_GetCurSel(hWnd);
            if (sel >= 0) {
                hWnd = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB2);
                ListBox_SetCurSel(hWnd, sel);
                hWnd = GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB3);
                ListBox_SetCurSel(hWnd, sel);
            }
            break;
        case ID_SC_PRIV_KEY_LB2:
        case ID_SC_PRIV_KEY_LB3:
            ListBox_SetCurSel(GetDlgItem(hDlg, LOWORD(wParam)), ListBox_GetCurSel(GetDlgItem(hDlg, ID_SC_PRIV_KEY_LB1)));
            break;
        }
        break;
    }

    return FALSE;
}

DialogItem addCertPKControls[] = {
    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SC_PK_STATIC1, 10, 180, 10, 10, 0xFFFF, 0x0082, 1},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SC_PK_STATIC2, 190, 100, 10, 10, 0xFFFF, 0x0082, 1},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SC_PK_STATIC3, 290, 100, 10, 10, 0xFFFF, 0x0082, 1},

    {WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_BORDER | WS_VSCROLL,
        ID_SC_PRIV_KEY_LB1, 10, 180, 20, 180, 0xFFFF, 0x0083, 1},

    {WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_BORDER | WS_VSCROLL,
        ID_SC_PRIV_KEY_LB2, 190, 100, 20, 180, 0xFFFF, 0x0083, 1},

    {WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_BORDER | WS_VSCROLL,
        ID_SC_PRIV_KEY_LB3, 290, 100, 20, 180, 0xFFFF, 0x0083, 1},

    {WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
        IDOK, 20, 60, 200, 15, 0xFFFF, 0x0080, 21},

    {WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
        IDCANCEL, 320, 60, 200, 15, 0xFFFF, 0x0080, 22}
};

LRESULT  DoManagePrivateKeysDialog(HINSTANCE hinst, HWND hwndOwner, Buffer& bChosen)
{
    HGLOBAL hgbl;
    LPDLGTEMPLATE lpdt;
    LPDLGITEMTEMPLATE lpdit;
    LPWORD lpw;
    LPWSTR lpwsz;
    LRESULT ret;
    int nchar;
    int Y = 10;
    int i = 0;
    int reduced = SC_PRIV_KEY_BUF_SZ / 2;
    int numCtrls = sizeof(addCertPKControls) / sizeof(DialogItem);

    pChosen = &bChosen;

    if (numCtrls == 0)
        return -1;

    if (numCtrls > 64)
        return -1;

    hgbl = GlobalAlloc(GMEM_ZEROINIT, SC_PRIV_KEY_BUF_SZ);
    if (!hgbl)
        return -1;

    lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);
    if (!lpdt)
    {
        GlobalFree(hgbl);
        return -1;
    }

    // Define a dialog box.
    RECT	rect;
    GetClientRect(hwndOwner, &rect);

    lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_MODALFRAME | WS_CAPTION;
    lpdt->cdit = numCtrls;
    lpdt->x = (SHORT)rect.right / 5;
    lpdt->y = (SHORT)rect.bottom / 5;
    lpdt->cx = SC_PRIV_KEY_DLG_WIDTH;
    lpdt->cy = SC_PRIV_KEY_DLG_HEIGHT;

    lpw = (LPWORD)(lpdt + 1);
    *lpw++ = 0;             // No menu
    *lpw++ = 0;             // Predefined dialog box class (by default)

    lpwsz = (LPWSTR)lpw;
    nchar = MultiByteToWideChar(
        CP_ACP,
        0,
        cInstalledSCPKcertStrings[0],
        -1,
        lpwsz,
        (int)strlen(cInstalledSCPKcertStrings[0]) + 1);
    lpw += nchar;

    for (i = 0; i < numCtrls; i++)
    {
        //first the label
        lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
        lpdit = (LPDLGITEMTEMPLATE)lpw;
        lpdit->x = addCertPKControls[i].dwX;
        lpdit->y = addCertPKControls[i].dwY;
        lpdit->cx = addCertPKControls[i].dwCX;
        lpdit->cy = addCertPKControls[i].dwCY;
        lpdit->id = addCertPKControls[i].dwId;    // Text identifier
        lpdit->style = addCertPKControls[i].dwStyle;

        lpw = (LPWORD)(lpdit + 1);
        *lpw++ = addCertPKControls[i].wClassLow;
        *lpw++ = addCertPKControls[i].wClassHi;        // Static class
        lpwsz = (LPWSTR)lpw;

        nchar = MultiByteToWideChar(CP_ACP, 0, cInstalledSCPKcertStrings[i + 1], -1, lpwsz,
            (int)strlen(cInstalledSCPKcertStrings[i + 1]) + 1);
        lpw += nchar;
        *lpw++ = 0;             // No creation data
    }

    //get installed SCARD here

    GlobalUnlock(hgbl);
    ret = DialogBoxIndirect(hinst,
        (LPDLGTEMPLATE)hgbl,
        hwndOwner,
        (DLGPROC)ManageSCARDkeysProc);
    GlobalFree(hgbl);
    return ret;
}

