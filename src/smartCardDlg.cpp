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
#include "threadPool.h"

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/ms644996(v=vs.85).aspx#modal_box
*/

enum IDS {
    ID_SCARD_PROGRESS_BAR = 500,
    ID_SCARD_USER_STATIC,
    ID_SCARD_USER_EDIT,
    ID_SCARD_COUNTRY_STATIC,
    ID_SCARD_COUNTRY_EDIT,
    ID_SCARD_STATE_STATIC,
    ID_SCARD_STATE_EDIT,
    ID_SCARD_CITY_STATIC,
    ID_SCARD_CITY_EDIT,
    ID_SCARD_ORG_STATIC,
    ID_SCARD_ORG_EDIT,
    ID_SCARD_UNIT_STATIC,
    ID_SCARD_UNIT_EDIT,
    ID_SCARD_UPN_STATIC,
    ID_SCARD_UPN_EDIT,
    ID_SCARD_EMAIL_STATIC,
    ID_SCARD_EMAIL_EDIT,
    ID_SCARD_STATUS_STATIC,
    ID_NULL
};

extern HFONT hAppFont;
extern COLORREF colorRed;
extern COLORREF colorGreen;
extern COLORREF colorBlue;

#define SC_PROGRESS_LIMIT 200
#define SC_PROGRESS_STEP 1

#define DLG_WIDTH 400
#define DLG_HEIGHT 300
#define MAX_TEXT 128
#define SCARD_NUM_CONTROLS (ID_NULL - ID_SCARD_PROGRESS_BAR + 2)
#define SCARD_NUM_STRINGS SCARD_NUM_CONTROLS+1
#define SCARD_STRING_SZ 128

#define SCARD_BUF_SZ SCARD_NUM_CONTROLS*1024

void SetLocalStatus(WCHAR* pwcText, bool bAppend);
BOOL
createUserCSR(
    char* subjUser,
    char* subjCntry,
    char* subjState,
    char* subjCity,
    char* subjOrg,
    char* subjUnit,
    char* subjUPN,
    char* subjEmail,
    char* password,
    char* scTemplate,
    ALG_ID algid,
    Buffer& bCSR);

bool
SaveCSR(
    Buffer& bCSR,
    char* pcName);

Buffer UserAttributes;
static BOOL Processing = FALSE;
static HWND hThisDlg = 0;
static WPARAM wEndParam = 0;

char cInstalledSCARDStrings[SCARD_NUM_STRINGS][SCARD_STRING_SZ] = {
    "Smartcard Initilization",
    "",
    "Common Name",
    "",
    "City",
    "",
    "Province/State",
    "",
    "Country",
    "",
    "Organization",
    "",
    "Unit",
    "",
    "E-Mail",
    "",
    "User Principal Name",
    "",
    "",
    "Process",
    "Close"
};

void SetCSRStatus(HWND hDlg, char* pcText)
{
    Buffer bMsg;
    HWND hWnd = 0;
    int sz = 0;

    if (!pcText) {
        return;
    }

    hWnd = GetDlgItem(hDlg, ID_SCARD_STATUS_STATIC);
    sz = GetWindowTextLengthA(hWnd);
    if (sz) {
        Buffer b;
        Buffer tmp(sz);
        b.Append((void*)pcText, strlen(pcText));
        bMsg.Append((void*)"\r\n", 2);
        GetWindowTextA(hWnd, (char*)tmp, sz);
        b.Append((void*)tmp, sz);
        bMsg.Append(b);
    }
    else {
        bMsg.Append((void*)pcText, strlen(pcText));
    }

    SetWindowTextA(hWnd, (char*)bMsg);
}

void*
ProgressProc(void* args) {
    HWND hWnd = GetDlgItem(hThisDlg, ID_SCARD_PROGRESS_BAR);
    while (!Processing) {
        Sleep(100);
    }

    while (Processing) {
        Sleep(100);
        SendMessage(hWnd, PBM_STEPIT, 0, 0);
    }

    SendMessage(hWnd, PBM_SETPOS, SC_PROGRESS_LIMIT, 0);

    return 0;
}

void*
CreateCard(void* args)
{
    HWND hWnd;
    char subjUser[MAX_TEXT];
    char subjCntry[MAX_TEXT];
    char subjState[MAX_TEXT];
    char subjCity[MAX_TEXT];
    char subjOrg[MAX_TEXT];
    char subjUnit[MAX_TEXT];
    char subjUPN[MAX_TEXT];
    char subjEmail[MAX_TEXT];
    char password[MAX_TEXT];
    char scTemplate[] = "SmartcardUser";
    ALG_ID algid = CALG_SHA_256;
    Buffer bCSR;

    Processing = TRUE;

    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_USER_EDIT);
        memset(subjUser, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjUser, MAX_TEXT-1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_COUNTRY_EDIT);
        memset(subjCntry, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjCntry, MAX_TEXT - 1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_STATE_EDIT);
        memset(subjState, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjState, MAX_TEXT - 1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_CITY_EDIT);
        memset(subjCity, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjCity, MAX_TEXT - 1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_ORG_EDIT);
        memset(subjOrg, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjOrg, MAX_TEXT - 1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_UNIT_EDIT);
        memset(subjUnit, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjUnit, MAX_TEXT - 1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_UPN_EDIT);
        memset(subjUPN, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjUPN, MAX_TEXT - 1);
    }
    {
        hWnd = GetDlgItem(hThisDlg, ID_SCARD_EMAIL_EDIT);
        memset(subjEmail, 0, MAX_TEXT);
        GetWindowTextA(hWnd, subjEmail, MAX_TEXT - 1);
    }

    if (strlen(subjUser) && strlen(subjCntry) && strlen(subjState) && strlen(subjCity) &&
        strlen(subjOrg) && strlen(subjUnit) && strlen(subjUPN) && strlen(subjEmail)) {
        SetCSRStatus(hThisDlg, (char*)"Starting to initialize the smartcard.\r\n");
        if (createUserCSR(subjUser, subjCntry, subjState, subjCity, subjOrg,
            subjUnit, subjUPN, subjEmail, password, scTemplate,
            algid, bCSR)) {
            SetCSRStatus(hThisDlg, (char*)"Success initializing the smartcard.\r\n");
            if (SaveCSR(bCSR, subjUPN)) {
                SetCSRStatus(hThisDlg, (char*)"Success uploading the CSR.\r\n");
            }
            else {
                SetCSRStatus(hThisDlg, (char*)"Failed to upload the CSR.\r\n");
            }
        }
        else {
            SetCSRStatus(hThisDlg, (char*)"Failed to initialize the smartcard.\r\n");
        }
    }

    Processing = FALSE;
    
    return 0;
}

LRESULT CALLBACK InstalledSCARDProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    HWND hWnd;

    hThisDlg = hDlg;

    switch (message)
    {
    case WM_INITDIALOG:
    {
        int8_t* tok = nullptr;
        int8_t* last = nullptr;

        Processing = FALSE;

        hWnd = GetDlgItem(hDlg, ID_SCARD_PROGRESS_BAR);
        SendMessage(hWnd, PBM_SETRANGE, 0, MAKELPARAM(0, SC_PROGRESS_LIMIT));
        SendMessage(hWnd, PBM_SETSTEP, (WPARAM)SC_PROGRESS_STEP, 0);
        SendMessage(hWnd, PBM_SETPOS, 0, 0);

        for (int i = ID_SCARD_PROGRESS_BAR; i < ID_NULL; i++) {
            hWnd = GetDlgItem(hDlg, i);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
        }
    
        hWnd = GetDlgItem(hDlg, IDOK);
        SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
        hWnd = GetDlgItem(hDlg, IDCANCEL);
        SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);

        tok = strToken((int8_t*)UserAttributes, (int8_t*)"\n", &last);
        while (tok) {
            char* seps = strstr((char*)tok, (char*)LDAP_SEPS);
            if (seps) {
                char* val = seps + strlen(LDAP_SEPS);
                seps[0] = 0;
                if (val) {
                    if (strcmp((char*)tok, "cn") == 0) {
                        hWnd = GetDlgItem(hDlg, ID_SCARD_USER_EDIT);
                        SetWindowTextA(hWnd, (char*)val);
                    }
                    else if (strcmp((char*)tok, "mail") == 0) {
                        hWnd = GetDlgItem(hDlg, ID_SCARD_EMAIL_EDIT);
                        SetWindowTextA(hWnd, (char*)val);
                    }
                    else if (strcmp((char*)tok, "l") == 0) {
                        hWnd = GetDlgItem(hDlg, ID_SCARD_CITY_EDIT);
                        SetWindowTextA(hWnd, (char*)val);
                    }
                    else if (strcmp((char*)tok, "st") == 0) {
                        hWnd = GetDlgItem(hDlg, ID_SCARD_STATE_EDIT);
                        SetWindowTextA(hWnd, (char*)val);
                    }
                    else if (strcmp((char*)tok, "c") == 0) {
                        hWnd = GetDlgItem(hDlg, ID_SCARD_COUNTRY_EDIT);
                        SetWindowTextA(hWnd, (char*)val);
                    }
                    else if (strcmp((char*)tok, "userPrincipalName") == 0) {
                        hWnd = GetDlgItem(hDlg, ID_SCARD_UPN_EDIT);
                        SetWindowTextA(hWnd, (char*)val);
                    }
                    else if (strcmp((char*)tok, "distinguishedName") == 0) {
                        char* dc = strstr((char*)val, (char*)"DC=");
                        if (dc) {
                            char* org = dc + 3;
                            if (org) {
                                char* comma = strstr(org, ",");
                                if (comma) {
                                    comma[0] = 0;
                                }
                                hWnd = GetDlgItem(hDlg, ID_SCARD_ORG_EDIT);
                                SetWindowTextA(hWnd, org);
                            }
                            dc[0] = 0;
                            {
                                char* ou = strstr((char*)val, (char*)"OU=");
                                if (ou) {
                                    char* unit = ou + 3;
                                    if (unit) {
                                        char* comma = strstr(unit, ",");
                                        if (comma) {
                                            comma[0] = 0;
                                        }
                                        hWnd = GetDlgItem(hDlg, ID_SCARD_UNIT_EDIT);
                                        SetWindowTextA(hWnd, unit);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            tok = strToken(0, (int8_t*)"\n", &last);
        }

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
        if (LOWORD(wParam) == IDOK)
        {
            threadPool::queueThread((void*)ProgressProc, (void*)&hDlg);
            threadPool::queueThread((void*)CreateCard, (void*)&hDlg);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            if (!Processing) {
                EndDialog(hDlg, LOWORD(wParam));
                return FALSE;
            }
        }
    }

    return FALSE;
}

DialogItem itemsHistory[] = {
    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_PROGRESS_BAR, DLG_WIDTH-155, 150, 5, 10, 0xFFFF, 0x0082, 1},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_USER_STATIC, 5, 100, 30, 10, 0xFFFF, 0x0082, 1},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_USER_EDIT, 105, 250, 30, 10, 0xFFFF, 0x0081, 2},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_CITY_STATIC, 5, 100, 45, 10, 0xFFFF, 0x0082, 3},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_CITY_EDIT, 105, 250, 45, 10, 0xFFFF, 0x0081, 4},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_STATE_STATIC, 5, 100, 60, 10, 0xFFFF, 0x0082, 5},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_STATE_EDIT, 105, 250, 60, 10, 0xFFFF, 0x0081, 6},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_COUNTRY_STATIC, 5, 100, 75, 10, 0xFFFF, 0x0082, 7},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_COUNTRY_EDIT, 105, 250, 75, 10, 0xFFFF, 0x0081, 8},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_ORG_STATIC, 5, 100, 90, 10, 0xFFFF, 0x0082, 9},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_ORG_EDIT, 105, 250, 90, 10, 0xFFFF, 0x0081, 10},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_UNIT_STATIC, 5, 100, 105, 10, 0xFFFF, 0x0082, 11},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_UNIT_EDIT, 105, 250, 105, 10, 0xFFFF, 0x0081, 12},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_EMAIL_STATIC, 5, 100, 120, 10, 0xFFFF, 0x0082, 13},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_EMAIL_EDIT, 105, 250, 120, 10, 0xFFFF, 0x0081, 14},

    {WS_CHILD | WS_VISIBLE | SS_LEFT,
        ID_SCARD_UPN_STATIC, 5, 100, 135, 10, 0xFFFF, 0x0082, 15},

    {WS_CHILD | WS_VISIBLE | SS_LEFT | WS_TABSTOP,
        ID_SCARD_UPN_EDIT, 105, 250, 135, 10, 0xFFFF, 0x0081, 16},

    {WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_BORDER | ES_READONLY | WS_VSCROLL,
        ID_SCARD_STATUS_STATIC, 5, 390, 155, 100, 0xFFFF, 0x0082, 1},

    {WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
        IDOK, 20, 60, 275, 15, 0xFFFF, 0x0080, 21},
    {WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
        IDCANCEL, 320, 60, 275, 15, 0xFFFF, 0x0080, 22}
};

LRESULT  DoSCardDialog(HINSTANCE hinst, HWND hwndOwner, Buffer& bAttribs)
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
    int reduced = SCARD_BUF_SZ / 2;
    int numCtrls = sizeof(itemsHistory) / sizeof(DialogItem);

    UserAttributes = bAttribs;

    if (numCtrls == 0)
        return -1;

    if (numCtrls > 64)
        return -1;

    hgbl = GlobalAlloc(GMEM_ZEROINIT, SCARD_BUF_SZ);
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
    lpdt->cx = DLG_WIDTH;
    lpdt->cy = DLG_HEIGHT;

    lpw = (LPWORD)(lpdt + 1);
    *lpw++ = 0;             // No menu
    *lpw++ = 0;             // Predefined dialog box class (by default)

    lpwsz = (LPWSTR)lpw;
    nchar = MultiByteToWideChar(
        CP_ACP,
        0,
        cInstalledSCARDStrings[0],
        -1,
        lpwsz,
        (int)strlen(cInstalledSCARDStrings[0]) + 1);
    lpw += nchar;

    for (i = 0; i < numCtrls; i++)
    {
        //first the label
        lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
        lpdit = (LPDLGITEMTEMPLATE)lpw;
        lpdit->x = itemsHistory[i].dwX;
        lpdit->y = itemsHistory[i].dwY;
        lpdit->cx = itemsHistory[i].dwCX;
        lpdit->cy = itemsHistory[i].dwCY;
        lpdit->id = itemsHistory[i].dwId;    // Text identifier
        lpdit->style = itemsHistory[i].dwStyle;

        lpw = (LPWORD)(lpdit + 1);
        if (i == 0) {
            char cls[] = PROGRESS_CLASSA;
            lpwsz = (LPWSTR)lpw;
            nchar = MultiByteToWideChar(CP_ACP, 0, cls, -1, lpwsz, (int)strlen(cls) + 1);
            lpw += nchar;
        }
        else if (i == (numCtrls-3)) {
            char cls[] = "RICHEDIT50W";
            lpwsz = (LPWSTR)lpw;
            nchar = MultiByteToWideChar(CP_ACP, 0, cls, -1, lpwsz, (int)strlen(cls) + 1);
            lpw += nchar;
        }
        else {
            *lpw++ = itemsHistory[i].wClassLow;
            *lpw++ = itemsHistory[i].wClassHi;        // Static class
        }
        lpwsz = (LPWSTR)lpw;

        nchar = MultiByteToWideChar( CP_ACP, 0, cInstalledSCARDStrings[i + 1], -1, lpwsz,
                                     (int)strlen(cInstalledSCARDStrings[i + 1]) + 1); 
        lpw += nchar;
        *lpw++ = 0;             // No creation data
    }

    //get installed SCARD here

    GlobalUnlock(hgbl);
    ret = DialogBoxIndirect(hinst,
        (LPDLGTEMPLATE)hgbl,
        hwndOwner,
        (DLGPROC)InstalledSCARDProc);
    GlobalFree(hgbl);
    return ret;
}

