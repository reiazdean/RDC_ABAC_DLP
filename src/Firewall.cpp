/********************************************************************++
Copyright (C) Microsoft. All Rights Reserved.

Abstract:
    This C++ file includes sample code that adds a outbound rule for
    the currently active profiles to allow a TCP connection using the
    Microsoft Windows Firewall APIs.

    https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-getting-firewall-settings
Portions of this file are based on Microsoft documentation samples.
Copyright (c) Microsoft Corporation.
Used under the terms of Microsoft's documentation reuse policy.
Modifications Copyright (c) 2026 REIAZDEAN CONSULTING INC.
--********************************************************************/
#include "stdafx.h"
#include "Utils.h"
#include <winevt.h>
#include <ws2tcpip.h>
#include <Mstcpip.h>
#include "Buffer.h"

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

// Forward declarations
HRESULT hrComInit = S_OK;
HRESULT hr = S_OK;
INetFwPolicy2* pNetFwPolicy2 = NULL;
DWORD PollInterval = 5000;//5 seconds

void SetLocalStatus(WCHAR* pwcText, bool bAppend);
BOOL MySystemShutdown();

void
ShowMessage(
    const char* format,
    ...
)
{
    char mess[MAX_PATH];
    
    memset(mess, 0, MAX_PATH);
    va_list args;
    va_start(args, format);
    _vsnprintf_s((char*)mess, MAX_PATH - 1, _TRUNCATE, (char*)format, args);
    va_end(args);

    MessageBoxA(NULL, mess, (char*)"Firewall", MB_OK);
}

int NumUdpConnsToIP(char* pcIP)
{
    int count = 0;
    DWORD dwSize = 0;
    MIB_UDPTABLE* pUdpTable = NULL;
    DWORD dwRetVal = 0;

    // Get the initial buffer size
    GetUdpTable(pUdpTable, &dwSize, TRUE);
    if (NO_ERROR != dwRetVal) {
        return 0;
    }

    // Allocate the buffer
    pUdpTable = (MIB_UDPTABLE*)malloc(dwSize);
    if (pUdpTable == NULL) {
        return 0;
    }

    // Get the UDP table
    dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE);
    if (NO_ERROR != dwRetVal) {
        free(pUdpTable);
        return 0;
    }

    // Display the UDP table
    for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
        char adr[128];
        ULONG sz = 128;
        if (ERROR_SUCCESS != RtlIpv4AddressToStringExA((struct in_addr*)&pUdpTable->table[i].dwLocalAddr, 0, adr, &sz)) {
            continue;
        }
        
        if (strcmp(adr, pcIP) == 0) {
            count++;
        }
    }

    free(pUdpTable);

    return count;
}

int NumTcpConnsToIP(char* pcIP)
{
    int count = 0;
    DWORD dwSize = 0;
    MIB_TCPTABLE2* pTcpTable = NULL;
    DWORD dwRetVal = 0;

    if (!pcIP) {
        return 0;
    }

    // Get the initial buffer size
    GetTcpTable2(pTcpTable, &dwSize, TRUE);
    if (NO_ERROR != dwRetVal) {
        return 0;
    }

    // Allocate the buffer
    pTcpTable = (MIB_TCPTABLE2*)malloc(dwSize);
    if (pTcpTable == NULL) {
        return 0;
    }

    // Get the TCP table
    dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE);
    if (NO_ERROR != dwRetVal) {
        free(pTcpTable);
        return 0;
    }

    // Display the TCP table
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        char adr[128];
        ULONG sz = 128;
        if (ERROR_SUCCESS != RtlIpv4AddressToStringExA((struct in_addr*)&pTcpTable->table[i].dwRemoteAddr, 0, adr, &sz)) {
            continue;
        }
        
        if (strcmp(adr, pcIP) == 0) {
            count++;
        }
    }

    free(pTcpTable);

    return count;
}

BOOL IsFirewallServiceRunning()
{
    BOOL bRC = FALSE;
    SC_HANDLE hSCM = 0;
    SC_HANDLE hService = 0;
    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;
    
    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        hService = OpenService(hSCM, L"MpsSvc", SERVICE_QUERY_STATUS);
        if (hService) {
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
                bRC = (serviceStatus.dwCurrentState == SERVICE_RUNNING);
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }
    
    return bRC;
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
    UNREFERENCED_PARAMETER(pContext);

    DWORD status = ERROR_SUCCESS;

    switch (action)
    {
    case EvtSubscribeActionError:
        break;
    case EvtSubscribeActionDeliver:
        MySystemShutdown();
        break;
    default:
        break;
    }

    return status; // The service ignores the returned status.
}

void* MonitorFirewall(void* args)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hSubscription = NULL;
    LPWSTR pwsPath = (LPWSTR)L"Security";
    LPWSTR pwsQuery = (LPWSTR)L"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and ((EventID=4950) or (EventID=4947))]]";
    HANDLE aWaitHandle = NULL;
    char* pcGwIP = (char*)args;
    if (!pcGwIP) {
        exit(0);
    }

    aWaitHandle = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!aWaitHandle) {
        exit(0);
    }

    // Subscribe to events beginning with the oldest event in the channel. The subscription
    // will return all current events in the channel and any future events that are raised
    // while the application is active.
    hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
        (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeStartAtOldestRecord);
    if (!hSubscription)
    {
        CloseHandle(aWaitHandle);
        exit(0);
    }

    do {
        if (!IsFirewallServiceRunning()) {
            MySystemShutdown();
        }

        if (NumTcpConnsToIP(pcGwIP) > 1) {
            MySystemShutdown();
        }

        if (NumUdpConnsToIP(pcGwIP) > 0) {
            MySystemShutdown();
        }

    } while (WaitForSingleObject(aWaitHandle, PollInterval) == WAIT_TIMEOUT);
    
    EvtClose(hSubscription);
    CloseHandle(aWaitHandle);

    return 0;
}

int DoOutboundDisallowedIPs(WCHAR* pwcName, WCHAR* pwcRange)
{
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;

    long CurrentProfilesBitMask = 0;

    BSTR bstrRuleName = SysAllocString(pwcName);
    BSTR bstrRuleDescription = SysAllocString(L"Block all traffic");
    BSTR bstrRuleGroup = SysAllocString(L"RDC Rule Group");
    BSTR bstrRuleRIPs = SysAllocString(pwcRange);
    BSTR bstrRulePorts = SysAllocString(L"*");

    // Retrieve INetFwRules
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr))
    {
        ShowMessage("get_Rules failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Retrieve Current Profiles bitmask
    hr = pNetFwPolicy2->get_CurrentProfileTypes(&CurrentProfilesBitMask);
    if (FAILED(hr))
    {
        ShowMessage("get_CurrentProfileTypes failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    CurrentProfilesBitMask = NET_FW_PROFILE2_ALL;

    // Create a new Firewall Rule object.
    hr = CoCreateInstance(
        __uuidof(NetFwRule),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule),
        (void**)&pFwRule);
    if (FAILED(hr))
    {
        ShowMessage("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Populate the Firewall Rule object
    pFwRule->put_Name(bstrRuleName);
    pFwRule->put_Description(bstrRuleDescription);
    pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
    pFwRule->put_RemoteAddresses(bstrRuleRIPs);
    pFwRule->put_RemotePorts(bstrRulePorts);
    pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
    pFwRule->put_Grouping(bstrRuleGroup);
    pFwRule->put_Profiles(CurrentProfilesBitMask);
    pFwRule->put_Action(NET_FW_ACTION_BLOCK);
    pFwRule->put_Enabled(VARIANT_TRUE);

    // Add the Firewall Rule
    hr = pFwRules->Add(pFwRule);
    if (FAILED(hr))
    {
        ShowMessage("Firewall Rule Add failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

Cleanup:

    // Free BSTR's
    SysFreeString(bstrRuleName);
    SysFreeString(bstrRuleDescription);
    SysFreeString(bstrRuleGroup);
    SysFreeString(bstrRuleRIPs);
    SysFreeString(bstrRulePorts);

    // Release the INetFwRule object
    if (pFwRule != NULL)
    {
        pFwRule->Release();
    }

    // Release the INetFwRules object
    if (pFwRules != NULL)
    {
        pFwRules->Release();
    }

    return 0;
}

// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        (void**)ppNetFwPolicy2);

    if (FAILED(hr))
    {
        ShowMessage("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

Cleanup:
    return hr;
}

int FirewallBlockAllButThisIP(Buffer& ipAdr)
{
    // Initialize COM.
    hrComInit = CoInitializeEx(
        0,
        COINIT_APARTMENTTHREADED
    );

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            ShowMessage("CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto Cleanup;
        }
    }

    // Retrieve INetFwPolicy2
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr))
    {
        goto Cleanup;
    }

    try {
        WCHAR wcRange[128];
        Buffer plus;
        Buffer minus;
        IncrementIp(ipAdr, plus);
        DecrementIp(ipAdr, minus);

        memset(wcRange, 0, sizeof(wcRange));
        swprintf_s(wcRange, sizeof(wcRange)/sizeof(WCHAR), L"0.0.0.0-%S", (char*)minus);
        DoOutboundDisallowedIPs((WCHAR*)L"A_RDC_OUTBOUND_RULE_1", wcRange);

        memset(wcRange, 0, sizeof(wcRange));
        swprintf_s(wcRange, sizeof(wcRange) / sizeof(WCHAR), L"%S-255.255.255.255", (char*)plus);
        DoOutboundDisallowedIPs((WCHAR*)L"A_RDC_OUTBOUND_RULE_2", wcRange);
        //now disallow all IPv6 addresses
       // DoOutboundDisallowedIPs((WCHAR*)L"A_RDC_OUTBOUND_RULE_3", (WCHAR*)L"::/0");
    }
    catch (...) {
        goto Cleanup;
    }
    
Cleanup:

    // Release the INetFwPolicy2 object
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
        pNetFwPolicy2 = NULL;
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit))
    {
        CoUninitialize();
    }

    return 0;
}
