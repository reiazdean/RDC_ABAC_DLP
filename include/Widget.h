#pragma once
#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>

using std::wstring;
using std::vector;

namespace ReiazDean {
    class Widget {
        //************   Cons/Destruction   ***************
    private:
    public:
        Widget();
        Widget(const Widget&) = delete;
        Widget(Widget&&) = delete;
        virtual ~Widget();

        //************   Class Attributes   ****************
    private:
    public:

        //************   Class Methods   *******************
    private:
        static vector<HWND> WindowHandles;
        static vector<Widget*> Widgets;
    protected:
    public:
        static void Cleanup();
        static void MoveWidgets(BOOL bPaint);
        //************ Instance Attributes  ****************
    private:
        HWND m_HWND;
        Widget* m_Parent;
        Widget* m_Above;
        Widget* m_ToLeft;
        Widget* m_ToRight;
        uint32_t m_X;
        uint32_t m_Height;
        uint32_t m_Y;
        uint32_t m_Width;
        bool m_LeftTopAnchor;
        bool m_RightTopAnchor;
        bool m_RightBottomAnchor;
        //Buffer m_ToolTip;
        
    public:

        //************ Instance Methods  *******************
    private:
        void getRect(RECT& rect);
    public:
        Widget& operator=(const Widget& original) = delete;
        Widget& operator=(Widget&& original) = delete;
        void SetAsRoot(HWND hWnd);
        void AddLeftTopAnchorWidget(uint32_t width, uint32_t height, Widget& w);
        void AddRightTopAnchorWidget(uint32_t width, uint32_t height, Widget& w);
        void AddRightBottomAnchorWidget(uint32_t width, uint32_t height, Widget& w);
        void AddSiblingWidgetBelow(uint32_t width, uint32_t height, Widget& w);
        void AddSiblingWidgetToRight(uint32_t width, uint32_t height, Widget& w);
        void AddSiblingWidgetToLeft(uint32_t width, uint32_t height, Widget& w);
        HWND CreateView(
            DWORD     dwExStyle,
            TCHAR*    lpClassName,
            TCHAR*    lpWindowName,
            DWORD     dwStyle,
            HMENU     hMenu,
            HINSTANCE hInstance,
            HFONT     hFont,
            TCHAR*    lpToolTip,
            HWND      hParentWnd,
            HWND      hWndTT
        );
        void SetToolTip(HWND hwndTT, HINSTANCE hInst, TCHAR* tt);
        void GetClientRect(RECT& rect);
        HWND GetHWnd() { return m_HWND; };
        void MoveView(BOOL bPaint);
    };
}

