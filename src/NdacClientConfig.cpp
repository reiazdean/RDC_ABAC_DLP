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


NdacClientConfig::NdacClientConfig()
{
#ifndef AUTH_SERVICE
    //myConfigItems.reserve(7);
    myConfigItems.push_back(ConfigItems{ AUTH_HOST_STRING, "", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ TLS_PORT_STRING, "1990", false, false, false, true });
    myConfigItems.push_back(ConfigItems{ TRUSTED_CA_FILE, "CAFile.crt", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ DILITHIUM_PUBLIC_FILE, "DilithiumPublic.dat", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ CLUSTER_MEMBERS_FILE, "ClientClusterMembers.conf", false, true, false, false });
    myConfigItems.push_back(ConfigItems{ KEY_STORAGE_PROVIDER, "Microsoft Smart Card Key Storage Provider", false, false, false, true });

    ReadConfigFile();
#endif
}

NdacClientConfig::~NdacClientConfig()
{
}

void NdacClientConfig::ReadConfigFile() {
    return DoReadConfigFile(CLIENT_CONF_FILE);
}

uint8_t NdacClientConfig::Save() {
    return DoSave(CLIENT_CONF_FILE);
}



