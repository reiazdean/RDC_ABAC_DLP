/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Widget.h"

using namespace ReiazDean;

#define _INSET  1
vector<HWND> Widget::WindowHandles;
vector<Widget*> Widget::Widgets;

void Widget::Cleanup() {
    for (const auto& hWnd : WindowHandles) {
#ifndef TEST_GUI
        TOOLINFOW ti = { 0 };
        SendMessage(hWnd, TTM_DELTOOL, 0, (LPARAM)(TOOLINFOW*)&ti);
#endif
        DestroyWindow(hWnd);
    }
    WindowHandles.clear();
    Widgets.clear();
}

void Widget::MoveWidgets(BOOL bPaint) {
    for (const auto& wgt : Widgets) {
        wgt->MoveView(bPaint);
    }
}

Widget::~Widget()
{
    //m_Children.clear();
    m_Parent = nullptr;
    m_ToLeft = nullptr;
    m_ToRight = nullptr;
    m_Above = nullptr;
}

Widget::Widget()
{
    m_HWND = 0;
    m_X = 0;
    m_Height = 0;
    m_Y = 0;
    m_Width = 0;
    m_Parent = nullptr;
    m_ToLeft = nullptr;
    m_ToRight = nullptr;
    m_Above = nullptr;
    m_LeftTopAnchor = false;
    m_RightTopAnchor = false;
    m_RightBottomAnchor = false;
}

void Widget::SetAsRoot(HWND hWnd)
{
    m_HWND = hWnd;
    m_Height = 100;
    m_Width = 100;
}

void Widget::GetClientRect(RECT& rect)
{
    if (m_HWND) {
        GetWindowRect(m_HWND, &rect);
    }
}

void Widget::AddLeftTopAnchorWidget(uint32_t width, uint32_t height, Widget& w)
{
    RECT rect;
  
    w.m_Height = height;
    w.m_Width = width;
    w.m_Parent = this;
    w.m_LeftTopAnchor = true;
    GetClientRect(rect);
    w.m_X = m_X + _INSET;
    w.m_Y = m_Y + _INSET;
    Widgets.push_back(&w);
}

void Widget::AddRightTopAnchorWidget(uint32_t width, uint32_t height, Widget& w)
{
    RECT rect;
    
    w.m_Height = height;
    w.m_Width = width;
    w.m_Parent = this;
    w.m_RightTopAnchor = true;
    GetClientRect(rect);
    w.m_X = rect.right * (100 - width) / 100;
    w.m_Y = m_Y + _INSET;
    Widgets.push_back(&w);
}

void Widget::AddRightBottomAnchorWidget(uint32_t width, uint32_t height, Widget& w)
{
    RECT rect;
    
    w.m_Height = height;
    w.m_Width = width;
    w.m_Parent = this;
    GetClientRect(rect);
    w.m_X = rect.right * (100 - width) / 100;
    w.m_Y = rect.bottom * (100 - height) / 100;
    w.m_RightBottomAnchor = true;
    Widgets.push_back(&w);
}

void Widget::AddSiblingWidgetBelow(uint32_t width, uint32_t height, Widget& w)
{
    RECT rect;

    if (!m_Parent) {
        throw("AddSiblingWidgetBelow invalid parent!");
    }
    
    w.m_Height = height;
    w.m_Width = width;
    m_Parent->GetClientRect(rect);
    w.m_X = m_X;
    w.m_Y = m_Y + (rect.bottom - rect.top) * m_Height / 100;
    w.m_Parent = m_Parent;
    w.m_Above = this;
    Widgets.push_back(&w);
}

void Widget::AddSiblingWidgetToRight(uint32_t width, uint32_t height, Widget& w)
{
    RECT rect;

    if (!m_Parent) {
        throw("AddSiblingWidgetToRight invalid parent!");
    }
    
    m_Parent->GetClientRect(rect);
    w.m_Height = height;
    w.m_Width = width;
    w.m_Y = m_Y;
    w.m_X = m_X + (rect.right - rect.left) * m_Width / 100;
    w.m_Parent = m_Parent;
    w.m_ToLeft = this;
    Widgets.push_back(&w);
}

void Widget::AddSiblingWidgetToLeft(uint32_t width, uint32_t height, Widget& w)
{
    RECT rect;

    if (!m_Parent) {
        throw("AddSiblingWidgetToLeft invalid parent!");
    }
    
    m_Parent->GetClientRect(rect);
    w.m_Height = height;
    w.m_Width = width;
    w.m_Y = m_Y;
    w.m_X = m_X - (rect.right - rect.left) * m_Width / 100;
    w.m_Parent = m_Parent;
    w.m_ToRight = this;
    Widgets.push_back(&w);
}

HWND Widget::CreateView(
    DWORD     dwExStyle,
    TCHAR* lpClassName,
    TCHAR* lpWindowName,
    DWORD     dwStyle,
    HMENU     hMenu,
    HINSTANCE hInstance,
    HFONT     hFont,
    TCHAR* lpToolTip,
    HWND      hParentWnd,
    HWND      hWndTT
)
{
    int nWidth, nHeight;
    RECT rect;

    if (!m_Parent) {
        return 0;
    }

    m_Parent->GetClientRect(rect);

    nWidth = (rect.right - rect.left) * m_Width / 100;
    nHeight = (rect.bottom - rect.top) * m_Height / 100;
    if (m_Above) {
        m_X = m_Above->m_X;
        m_Y = m_Above->m_Y + (rect.bottom - rect.top) * m_Above->m_Height / 100;
    }
    else if (m_ToLeft) {
        m_X = m_ToLeft->m_X + (rect.right - rect.left) * m_ToLeft->m_Width / 100;
        m_Y = m_ToLeft->m_Y;
    }
    else if (m_ToRight) {
        m_X = m_ToRight->m_X - (rect.right - rect.left) * m_Width / 100;
        m_Y = m_ToRight->m_Y;
    }
    else if (m_RightBottomAnchor) {
        m_X = (rect.right - rect.left) * (100 - m_Width) / 100;
        m_Y = (rect.bottom - rect.top) * (100 - m_Height) / 100;
    }
    else if (m_RightTopAnchor) {
        m_X = (rect.right - rect.left) * (100 - m_Width) / 100;
        m_Y = m_Parent->m_Y + _INSET;
    }
    
    m_HWND = CreateWindowEx(
        dwExStyle,
        lpClassName,
        lpWindowName,
        dwStyle,
        m_X,
        m_Y,
        nWidth,
        nHeight,
        (hParentWnd == 0) ? m_Parent->GetHWnd() : hParentWnd,
        hMenu,
        hInstance,
        0
    );

    if (m_HWND == 0) {
        throw("CreateWindowEx failed!");
    }

    SendMessage(m_HWND, WM_SETFONT, (WPARAM)hFont, TRUE);
    if (lpToolTip) {
        SetToolTip(hWndTT, hInstance, lpToolTip);
    }

    //add to the beginning of the vector
    WindowHandles.insert(WindowHandles.begin(), m_HWND);

    return m_HWND;
}

void Widget::SetToolTip(HWND hwndTT, HINSTANCE hInst, TCHAR* tt)
{
#ifndef TEST_GUI
    if (m_HWND) {
        LRESULT res;
        TOOLINFOW ti = { 0 };
        ti.cbSize = TTTOOLINFO_V1_SIZE;//sizeof(TOOLINFOW);
        ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
        ti.hwnd = m_HWND;
        ti.uId = (UINT_PTR)m_HWND;
        ti.hinst = hInst;
        ti.lpszText = tt;

        GetWindowRect(m_HWND, &ti.rect);

        // Associate the tooltip with the "tool" window.
        res = SendMessage(hwndTT, TTM_ADDTOOLW, 0, (LPARAM)(TOOLINFOW*)&ti);
    }
#endif
}

void Widget::MoveView(BOOL bPaint)
{
    int nWidth, nHeight;
    RECT rect;

    if (!m_Parent) {
        return;
    }

    m_Parent->GetClientRect(rect);

    nWidth = (rect.right - rect.left) * m_Width / 100;
    nHeight = (rect.bottom - rect.top) * m_Height / 100;
    if (m_Above) {
        m_X = m_Above->m_X;
        m_Y = m_Above->m_Y + (rect.bottom - rect.top) * m_Above->m_Height / 100;
    }
    else if (m_ToLeft) {
        m_X = m_ToLeft->m_X + (rect.right - rect.left) * m_ToLeft->m_Width / 100;
        m_Y = m_ToLeft->m_Y;
    }
    else if (m_ToRight) {
        m_X = m_ToRight->m_X - (rect.right - rect.left) * m_Width / 100;
        m_Y = m_ToRight->m_Y;
    }
    else if (m_RightBottomAnchor) {
        m_X = (rect.right - rect.left) * (100 - m_Width) / 100;
        m_Y = (rect.bottom - rect.top) * (100 - m_Height) / 100;
    }
    else if (m_RightTopAnchor) {
        m_X = (rect.right - rect.left) * (100 - m_Width) / 100;
        m_Y = m_Parent->m_Y + _INSET;
    }
    
    ShowWindow(m_HWND, SW_HIDE);
    MoveWindow(m_HWND, m_X, m_Y, nWidth, nHeight, bPaint);
    ShowWindow(m_HWND, SW_SHOW);
}
