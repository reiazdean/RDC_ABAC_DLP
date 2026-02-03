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
#include "Buffer.h"
#include "NdacConfig.h"

using namespace std;

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/ms644996(v=vs.85).aspx#modal_box
*/

#define ID_BASE 500
#define DLG_TITLE "Client Configuration"
#define MAX_CHARS 128

extern HFONT hAppFont;
extern COLORREF colorRed;
extern COLORREF colorGreen;
extern COLORREF colorBlue;

static BOOL Working = FALSE;
static HWND hThisDlg = 0;
static WPARAM wEndParam = 0;
static int LastID = 0;

bool Save() {
	bool bRc = false;
	NdacClientConfig& clienCfg = NdacClientConfig::GetInstance();

	for (int i = ID_BASE; i < LastID; i += 2) {
		HWND hStatic, hEdit;
		char l[MAX_CHARS];
		char m[MAX_CHARS];
		hStatic = GetDlgItem(hThisDlg, i);
		hEdit = GetDlgItem(hThisDlg, i+1);
		memset(l, 0, MAX_CHARS);
		memset(m, 0, MAX_CHARS);
		GetWindowTextA(hStatic, l, MAX_CHARS - 1);
		GetWindowTextA(hEdit, m, MAX_CHARS - 1);
		if (strcmp(l, AUTH_HOST_STRING) == 0) {
			Buffer bFileName = clienCfg.GetValue(CLUSTER_MEMBERS_FILE);
			if (bFileName.Size() > 0) {
				saveToFile((int8_t*)bFileName, (int8_t*)m, (uint32_t)strlen(m));
			}
		}
		else {
			clienCfg.SetValue(l, m);
		}
	}
	clienCfg.Save();

	Working = false;

	bRc = true;

	return bRc;
}


LRESULT CALLBACK ConfigProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	HWND hWnd;

	hThisDlg = hDlg;

	switch (message)
	{
	case WM_INITDIALOG:
	{
		Working = FALSE;

		
		for (int i = ID_BASE; i <= LastID; i++) {
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
			Save();
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		else if (LOWORD(wParam) == IDCANCEL)
		{
			if (!Working) {
				EndDialog(hDlg, LOWORD(wParam));
				return FALSE;
			}
		}
	}

	return FALSE;
}

DialogItem cfgControls[] = {
	{WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
		IDOK, 20, 60, 200, 15, 0xFFFF, 0x0080, 21},
	{WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
		IDCANCEL, 320, 60, 200, 15, 0xFFFF, 0x0080, 22}
};

LRESULT  DoConfigDialog(HINSTANCE hinst, HWND hwndOwner)
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
	SHORT numItems = 0;
	SHORT numCtrls = 0;
	SHORT dwX = 10;
	SHORT dwY = 10;
	SHORT dwHeight = 10;
	SHORT dwWidth = 90;
	char cls[] = "RICHEDIT50W";
	NdacClientConfig& clienCfg = NdacClientConfig::GetInstance();

	vector<ConfigItems>& configs = clienCfg.GetConfigItems();
	numItems = (SHORT)configs.size();
	numCtrls = numItems * 2 + 2;

	if (numCtrls == 0)
		return -1;

	if (numCtrls > 64)
		return -1;

	hgbl = GlobalAlloc(GMEM_ZEROINIT, (size_t)numCtrls * 1024);
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
	lpdt->cx = 400;
	lpdt->cy = numItems * 20 + 40 + 60;

	lpw = (LPWORD)(lpdt + 1);
	*lpw++ = 0;             // No menu
	*lpw++ = 0;             // Predefined dialog box class (by default)

	lpwsz = (LPWSTR)lpw;
	nchar = MultiByteToWideChar(
		CP_ACP,
		0,
		DLG_TITLE,
		-1,
		lpwsz,
		(int)strlen(DLG_TITLE) + 1);
	lpw += nchar;

	for (const auto& tup : configs) {
		string s = "";
		//first the label
		lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
		lpdit = (LPDLGITEMTEMPLATE)lpw;
		lpdit->x = dwX;
		lpdit->y = dwY;
		lpdit->cx = dwWidth;
		lpdit->cy = dwHeight;
		lpdit->id = ID_BASE + i * 2;    // Text identifier
		lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT;

		lpw = (LPWORD)(lpdit + 1);
		*lpw++ = 0xFFFF;
		*lpw++ = 0x0082;        // Static class
		lpwsz = (LPWSTR)lpw;

		nchar = MultiByteToWideChar(CP_ACP, 0, tup.sKey.c_str(), -1, lpwsz, (int)strlen(tup.sKey.c_str()) + 1);
		lpw += nchar;
		*lpw++ = 0;             // No creation data

		//Now the edit box
		lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
		lpdit = (LPDLGITEMTEMPLATE)lpw;
		lpdit->x = dwX + dwWidth;
		lpdit->y = dwY;
		lpdit->cx = dwWidth * 3;
		lpdit->cy = dwHeight;
		lpdit->id = ID_BASE + i * 2 + 1;    // Text identifier
		LastID = lpdit->id;
		lpw = (LPWORD)(lpdit + 1);
		if (tup.sKey.compare(AUTH_HOST_STRING) == 0) {
			Buffer bFileName = clienCfg.GetValue(CLUSTER_MEMBERS_FILE);
			Buffer bData;
			if (bFileName.Size() > 0) {
				readFile((char*)bFileName, bData);
				if (bData.Size() > 0) {
					s = string((char*)bData);
				}
				else {
					s = "";
				}
			}
			
			lpdit->cy = 60;
			lpwsz = (LPWSTR)lpw;
			nchar = MultiByteToWideChar(CP_ACP, 0, cls, -1, lpwsz, (int)strlen(cls) + 1);
			lpw += nchar;
			lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT | ES_MULTILINE | ES_WANTRETURN | WS_VSCROLL;
			dwY = dwY + 60;
		}
		else {
			s = clienCfg.GetValue(tup.sKey.c_str());//s = std::get<1>(tup).c_str();
			
			lpdit->cy = dwHeight;
			lpwsz = (LPWSTR)lpw;
			nchar = MultiByteToWideChar(CP_ACP, 0, cls, -1, lpwsz, (int)strlen(cls) + 1);
			lpw += nchar;
			lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT | ES_MULTILINE | ES_WANTRETURN;
		}
		
		lpwsz = (LPWSTR)lpw;
		
		nchar = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, lpwsz, (int)strlen(s.c_str()) + 1);
		lpw += nchar;
		*lpw++ = 0;             // No creation data

		dwY = dwY + dwHeight + 5;
		i++;
	}

	lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->x = dwX;
	lpdit->y = dwY + 20;
	lpdit->cx = 60;
	lpdit->cy = 15;
	lpdit->id = IDOK;    // Text identifier
	lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP;

	lpw = (LPWORD)(lpdit + 1);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0080;        // Static class
	lpwsz = (LPWSTR)lpw;

	nchar = MultiByteToWideChar(CP_ACP, 0, "Save", -1, lpwsz, 5);
	lpw += nchar;
	*lpw++ = 0;             // No creation data

	lpw = lpwAlign(lpw);    // Align DLGITEMTEMPLATE on DWORD boundary
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->x = 400 - dwX - 60;
	lpdit->y = dwY + 20;
	lpdit->cx = 60;
	lpdit->cy = 15;
	lpdit->id = IDCANCEL;    // Text identifier
	lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP;

	lpw = (LPWORD)(lpdit + 1);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0080;        // Static class
	lpwsz = (LPWSTR)lpw;

	nchar = MultiByteToWideChar(CP_ACP, 0, "Cancel", -1, lpwsz, 7);
	lpw += nchar;
	*lpw++ = 0;             // No creation data

	//get installed SCARD here

	GlobalUnlock(hgbl);
	ret = DialogBoxIndirect(hinst,
		(LPDLGTEMPLATE)hgbl,
		hwndOwner,
		(DLGPROC)ConfigProc);
	GlobalFree(hgbl);
	return ret;
}

