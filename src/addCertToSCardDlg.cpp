/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <shellapi.h>
#include <iostream>
#include <commctrl.h>
#include <stdio.h>
#include <Windowsx.h>
#include <msi.h>
#include "threadPool.h"
#include "NdacConfig.h"
#include "KSPkey.h"
#include "x509class.h"

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/ms644996(v=vs.85).aspx#modal_box
*/

extern bool AddCertToCard(Buffer& bUPN, Buffer& bCert);
extern bool DownloadCertificate(Buffer& bUPN, Buffer& bCert);

enum IDS {
	ID_SC_CERT_PROGRESS_BAR = 500,
	ID_SC_CERT_STATUS_STATIC,
	ID_SC_NULL
};

extern HFONT hAppFont;
extern COLORREF colorRed;
extern COLORREF colorGreen;
extern COLORREF colorBlue;

#define SC_CERT_PROGRESS_LIMIT 200
#define SC_CERT_PROGRESS_STEP 1

#define SC_CERT_DLG_WIDTH 400
#define SC_CERT_DLG_HEIGHT 230
#define SC_CERT_MAX_TEXT 128
#define SC_CERT_NUM_CONTROLS 4
#define SC_CERT_NUM_STRINGS SC_CERT_NUM_CONTROLS+1
#define SC_CERT_STRING_SZ 128

#define SC_CERT_BUF_SZ SC_CERT_NUM_CONTROLS*1024

extern Buffer UserPrincipalName;
static std::atomic<BOOL> Working = FALSE;
static HWND hThisDlg = 0;
static WPARAM wEndParam = 0;

char cInstalledSCcertStrings[SC_CERT_NUM_STRINGS][SC_CERT_STRING_SZ] = {
	"Add Certificate To Smartcard",
	"",
	"",
	"Process",
	"Close"
};

void SetStatus(HWND hDlg, char* pcText)
{
	Buffer bMsg;
	HWND hWnd = 0;
	int sz = 0;

	if (!pcText) {
		return;
	}

	hWnd = GetDlgItem(hDlg, ID_SC_CERT_STATUS_STATIC);
	sz = GetWindowTextLengthA(hWnd);
	if (sz) {
		Buffer b;
		Buffer tmp(sz);
		b.Append((void*)pcText, (uint32_t)strlen(pcText));
		bMsg.Append((void*)"\r\n", 2);
		GetWindowTextA(hWnd, (char*)tmp, sz);
		b.Append((void*)tmp, sz);
		bMsg.Append(b);
	}
	else {
		bMsg.Append((void*)pcText, (uint32_t)strlen(pcText));
	}

	SetWindowTextA(hWnd, (char*)bMsg);
}

bool
ValidateDownloadedCert(Buffer& bDownloadedCert) {
	bool        bRc = false;
	Buffer      bSignature;
	Buffer      bHash;

	try {
		NdacClientConfig& ccfg = NdacClientConfig::GetInstance();
		Buffer bKSP_w = ccfg.GetValueW(KEY_STORAGE_PROVIDER);

		KSPkey ksp((WCHAR*)bKSP_w);
		if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)MY_SMARTCARD_CONTAINER, 0)) {
			Sha256((uint8_t*)"0123456789", 10, bHash);
			if (ERROR_SUCCESS == ksp.SignHash((uint8_t*)bHash, bHash.Size(), bSignature)) {
				bRc = RSA_VerifyBIO(
					(uint8_t*)bDownloadedCert, bDownloadedCert.Size(),
					(uint8_t*)bHash, bHash.Size(),
					(uint8_t*)bSignature, bSignature.Size());
			}

		}
	}
	catch (...) {
		return false;
	}

	return bRc;
}

void*
AddCertProgressProc(void* args) {
	HWND hWnd = GetDlgItem(hThisDlg, ID_SC_CERT_PROGRESS_BAR);

	while (!Working) {
		Sleep(100);
	}

	while (Working) {
		Sleep(100);
		SendMessage(hWnd, PBM_STEPIT, 0, 0);
	}

	SendMessage(hWnd, PBM_SETPOS, SC_CERT_PROGRESS_LIMIT, 0);

	return 0;
}

bool AddCertToCard(Buffer& bUPN, Buffer& bCert) {
	try {
		NdacClientConfig& ccfg = NdacClientConfig::GetInstance();
		Buffer bKSP_w = ccfg.GetValueW(KEY_STORAGE_PROVIDER);

		KSPkey ksp((WCHAR*)bKSP_w);
		if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)MY_SMARTCARD_CONTAINER, 0)) {
			if (ERROR_SUCCESS == ksp.SetCertificate(bCert)) {
				return true;
			}
		}
	}
	catch (...) {
		return false;
	}
	return false;
}

bool
GetCertFromP7B(
	Buffer& bP7B,
	Buffer& bUserCert
)
{
	bool bRc = false;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	CRYPT_DATA_BLOB blob;
	blob.pbData = (uint8_t*)bP7B;      // BYTE* containing your P7B data
	blob.cbData = bP7B.Size();       // size in bytes
	
	BOOL ok = CryptQueryObject(
		CERT_QUERY_OBJECT_BLOB,
		&blob,
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
			Buffer bUPN;
			Buffer b((char*)pCert->pbCertEncoded, pCert->cbCertEncoded);
			Certificate cert(b);
			cert.GetUPNSubjectAltName(bUPN);
			if (bUPN.Size() > 0) {
				Buffer bWCupn;
				GetWcharFromUtf8(bUPN, bWCupn);
				if (bWCupn.Size() > 0) {
					if (wcscmp((WCHAR*)bWCupn, (WCHAR*)UserPrincipalName) == 0) {
						bUserCert = b;
						bRc = true;
					}
				}
			}
		}
		CertCloseStore(hStore, 0);
	}
	
	if (hMsg)
		CryptMsgClose(hMsg);

	return bRc;
}

void*
AddCertificateToCard(void* args)
{
	Buffer bP7B;
	Buffer bCert;

	Working = TRUE;

	try {
		SetStatus(hThisDlg, (char*)"Starting to download P7B data.\r\n");
		if (DownloadCertificate(UserPrincipalName, bP7B)) {
			if (GetCertFromP7B(bP7B, bCert)) {
				if (ValidateDownloadedCert(bCert)) {
					SetStatus(hThisDlg, (char*)"Starting to add certificate to the card.\r\n");
					if (AddCertToCard(UserPrincipalName, bCert)) {
						SetStatus(hThisDlg, (char*)"Success adding the certificate to the card.\r\n");
					}
					else {
						SetStatus(hThisDlg, (char*)"Failed to add the certificate to the card.\r\n");
					}
				}
				else {
					SetStatus(hThisDlg, (char*)"Failed to validate the downloaded certificate.\r\n");
				}
			}
			else {
				SetStatus(hThisDlg, (char*)"Invalid P7B file.\r\n");
			}
		}
		else {
			SetStatus(hThisDlg, (char*)"Failed to download P7B contents.\r\n");
		}
	}
	catch (...) {
		SetStatus(hThisDlg, (char*)"Failed to process certificate addition.\r\n");
	}

	Working = FALSE;
	
	return 0;
}

LRESULT CALLBACK InstallCertToSCARDProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	HWND hWnd;

	hThisDlg = hDlg;

	switch (message)
	{
	case WM_INITDIALOG:
	{
		Working = FALSE;

		hWnd = GetDlgItem(hDlg, ID_SC_CERT_PROGRESS_BAR);
		SendMessage(hWnd, PBM_SETRANGE, 0, MAKELPARAM(0, SC_CERT_PROGRESS_LIMIT));
		SendMessage(hWnd, PBM_SETSTEP, (WPARAM)SC_CERT_PROGRESS_STEP, 0);
		SendMessage(hWnd, PBM_SETPOS, 0, 0);

		for (int i = ID_SC_CERT_PROGRESS_BAR; i < ID_SC_NULL; i++) {
			hWnd = GetDlgItem(hDlg, i);
			SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
		}

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
		if (LOWORD(wParam) == IDOK)
		{
			wEndParam = wParam;
			threadPool::queueThread((void*)AddCertProgressProc, 0);
			threadPool::queueThread((void*)AddCertificateToCard, 0);
			return TRUE;
		}
		else if (LOWORD(wParam) == IDCANCEL)
		{
			if (!Working) {
				UserPrincipalName.Finalize();
				EndDialog(hDlg, LOWORD(wParam));
				return FALSE;
			}
		}
	}

	return FALSE;
}

DialogItem addCertControls[] = {
	{WS_CHILD | WS_VISIBLE | SS_LEFT,
		ID_SC_CERT_PROGRESS_BAR, SC_CERT_DLG_WIDTH - 155, 150, 5, 10, 0xFFFF, 0x0082, 1},

	{WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_BORDER | ES_READONLY | WS_VSCROLL,
		ID_SC_CERT_STATUS_STATIC, 10, 380, 20, 180, 0xFFFF, 0x0082, 1},

	{WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
		IDOK, 20, 60, 200, 15, 0xFFFF, 0x0080, 21},
	{WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
		IDCANCEL, 320, 60, 200, 15, 0xFFFF, 0x0080, 22}
};

LRESULT  DoAddCertToSCardDialog(HINSTANCE hinst, HWND hwndOwner, Buffer& bUPN)
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
	int reduced = SC_CERT_BUF_SZ / 2;
	int numCtrls = sizeof(addCertControls) / sizeof(DialogItem);

	UserPrincipalName = bUPN;

	if (numCtrls == 0)
		return -1;

	if (numCtrls > 64)
		return -1;

	hgbl = GlobalAlloc(GMEM_ZEROINIT, SC_CERT_BUF_SZ);
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
	lpdt->cx = SC_CERT_DLG_WIDTH;
	lpdt->cy = SC_CERT_DLG_HEIGHT;

	lpw = (LPWORD)(lpdt + 1);
	*lpw++ = 0;             // No menu
	*lpw++ = 0;             // Predefined dialog box class (by default)

	lpwsz = (LPWSTR)lpw;
	nchar = MultiByteToWideChar(
		CP_ACP,
		0,
		cInstalledSCcertStrings[0],
		-1,
		lpwsz,
		(int)strlen(cInstalledSCcertStrings[0]) + 1);
	lpw += nchar;

	for (i = 0; i < numCtrls; i++)
	{
		//first the label
		lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
		lpdit = (LPDLGITEMTEMPLATE)lpw;
		lpdit->x = addCertControls[i].dwX;
		lpdit->y = addCertControls[i].dwY;
		lpdit->cx = addCertControls[i].dwCX;
		lpdit->cy = addCertControls[i].dwCY;
		lpdit->id = addCertControls[i].dwId;    // Text identifier
		lpdit->style = addCertControls[i].dwStyle;

		lpw = (LPWORD)(lpdit + 1);
		if (i == 0) {
			char cls[] = PROGRESS_CLASSA;
			lpwsz = (LPWSTR)lpw;
			nchar = MultiByteToWideChar(CP_ACP, 0, cls, -1, lpwsz, (int)strlen(cls) + 1);
			lpw += nchar;
		}
		else if (i == 1) {
			char cls[] = "RICHEDIT50W";
			lpwsz = (LPWSTR)lpw;
			nchar = MultiByteToWideChar(CP_ACP, 0, cls, -1, lpwsz, (int)strlen(cls) + 1);
			lpw += nchar;
		}
		else {
			*lpw++ = addCertControls[i].wClassLow;
			*lpw++ = addCertControls[i].wClassHi;        // Static class
		}
		lpwsz = (LPWSTR)lpw;

		nchar = MultiByteToWideChar(CP_ACP, 0, cInstalledSCcertStrings[i+1], -1, lpwsz,
			(int)strlen(cInstalledSCcertStrings[i+1]) + 1);
		lpw += nchar;
		*lpw++ = 0;             // No creation data
	}

	//get installed SCARD here

	GlobalUnlock(hgbl);
	ret = DialogBoxIndirect(hinst,
		(LPDLGTEMPLATE)hgbl,
		hwndOwner,
		(DLGPROC)InstallCertToSCARDProc);
	GlobalFree(hgbl);
	return ret;
}

