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

#ifdef AUTH_SERVICE
#define     CONF_DIR                   "\\ReiazDeanIncServer"
#else
#define     CONF_DIR                   "\\ReiazDeanIncClient"
#endif
#define     CLIENT_CONF_FILE           "\\ReiazDeanClient.conf"
#define     SERVER_CONF_FILE           "\\ReiazDeanServer.conf"

#ifdef AUTH_SERVICE
extern Buffer* pPasswordBuffer;
EVP_PKEY* GenerateOrOpenRSA();
#endif

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

NdacConfig::NdacConfig()
{
    isValid = false;
    determinePath();
}

void NdacConfig::determinePath()
{
    errno_t e = -1;
    myFilePath = "";
    try {
        size_t requiredSize = 0;
        e = getenv_s(&requiredSize, 0, 0, "PROGRAMDATA");
        if (requiredSize > 0)
        {
            Buffer bEnv(requiredSize);
            e = getenv_s(&requiredSize, (char*)bEnv, requiredSize, "PROGRAMDATA");
            myFilePath += (char*)bEnv;
            myFilePath += (char*)CONF_DIR;
        }
        mySeps = "\\";
    }
    catch (...) {
        myFilePath = "";
    }
}

void NdacConfig::SetValue(const string& key, const string& value)
{
    for (auto& tup : myConfigItems) {
        string& ck = tup.sKey;
        if ((key.compare(ck) == 0) && tup.bUserModifiable) {
            tup.sValue = value;
        }
    }
}

NdacConfig::~NdacConfig()
{

}

void NdacConfig::Finalize()
{
    for (auto& tup : myConfigItems) {
        tup.sKey = "";
        tup.sValue = "";
    }
    myConfigItems.clear();
    myFilePath = "";
    mySeps = "";
}

string NdacConfig::GetValue(const string& pcTag)
{
    string pcRet = "";

    for (auto& tup : myConfigItems) {
        if (tup.sKey == pcTag)
        {
            if (tup.bPathRequired) {
                return myFilePath + mySeps + tup.sValue;
            }
            return  tup.sValue;
        }
    }

    return pcRet;
}

void NdacConfig::GetValue(const char* pcVal, Buffer& val)
{
    if (pcVal) {
        try {
            string v = GetValue(string(pcVal));
            val.Clear();
            val.Append(v);
        }
        catch (...) {
            val.Clear();
        }
    }
}

Buffer NdacConfig::GetValue(const char* pcVal)
{
    Buffer val;
    if (pcVal) {
        try {
            string v = GetValue(string(pcVal));
            val.Append(v);
        }
        catch (...) {
            return val;
        }
    }
    return val;
}

Buffer NdacConfig::GetValueW(const char* pcVal)
{
    Buffer wVal;
    if (pcVal) {
        try {
            Buffer val = GetValue(pcVal);
            if (val.Size() > 0) {
                GetWcharFromUtf8((char*)val, wVal);
                wVal.NullTerminate_w();
            }
        }
        catch (...) {
            return wVal;
        }
    }
    return wVal;
}

void NdacConfig::DoReadConfigFile(const char* filename)
{
    char buf[1024];
    FILE* fp = nullptr;
    Buffer bFile(myFilePath);

    if (!filename) {
        return;
    }

    bFile.Append((void*)filename, strlen(filename));
    bFile.NullTerminate();

    fp = f_open_f((char*)bFile, (char*)"r");
    if (!fp)
        return;

    memset(buf, 0, sizeof(buf));
    while (fgets(buf, sizeof(buf) - 1, fp)) {
        int8_t* key = nullptr;
        int8_t* val = nullptr;

        if (buf[strlen((char*)buf) - 1] == 0x0A) {
            buf[strlen((char*)buf) - 1] = 0x0;
        }
        if (buf[strlen((char*)buf) - 1] == 0x0D) {
            buf[strlen((char*)buf) - 1] = 0x0;
        }

        key = strToken((int8_t*)buf, (int8_t*)"=", &val);
        if (key && val) {
            string k((char*)key);
            string v((char*)val);
            SetValue(k, v);
        }
        memset(buf, 0, sizeof(buf));
    }

    fclose(fp);
    isValid = true;

    return;
}

uint8_t NdacConfig::DoSave(const char* filename)
{
    size_t requiredSize = 0;
    string output = "";
    Buffer bFile(myFilePath);

    if (!filename) {
        return 0;
    }

    Buffer bDir = bFile;
    bDir.NullTerminate();
    if (!CreateDirectoryA((char*)bDir, 0)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            return 0;
        }
    }

    bFile.Append((void*)filename, strlen(filename));
    bFile.NullTerminate();

    for (const auto& tup : myConfigItems) {
        output += tup.sKey;
        output += "=";
        output += tup.sValue;
        output += (char*)"\n";
    }

    return saveToFile((int8_t*)bFile, (int8_t*)output.c_str(), (uint32_t)output.length());
}
