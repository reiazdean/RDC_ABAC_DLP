/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "LocalClient.h"
#include "Utils.h"

using namespace ReiazDean;

#ifndef AUTH_SERVICE
void SetCommandStatus(ReiazDean::Commands cmd, ReiazDean::Responses resp);
#endif

LocalClient::LocalClient() {
    mUnixSock = 0;
    m_Established = false;
#ifndef AUTH_SERVICE
    try {
        Buffer gwIP;
        if (GetGatewayIP(gwIP)) {
            mUnixSock = OpenClientInetSocket((char*)gwIP, 1991);
        }
    }
    catch (...) {
        mUnixSock = 0;
    }
#else
    mUnixSock = OpenUnixSocket(false);
#endif
    if (mUnixSock > 0) {
        m_Established = (0 == ExchangeECDH());
    }
}

LocalClient::~LocalClient() {

    if (mUnixSock > 0) {
        CloseSocket(mUnixSock);
    }

}

int LocalClient::ExchangeECDH() {
    Buffer          in, out;
    CommandHeader   ch;
    uint8_t*        pcOSpubKey = m_ECKeyPair.GetPublicKey();
    uint32_t        szOSpub = m_ECKeyPair.GetPublicKeySize();

    try {
        ch.command = Commands::CMD_EXCHANGE_ECDH_KEYS;
        ch.szData = szOSpub;
        out.Append(&ch, sizeof(ch));
        out.Append(pcOSpubKey, szOSpub);

        NonBlockingWrite(mUnixSock, out);

        if ((uint32_t)NonBlockingRead(mUnixSock, in) < szOSpub) {
            CloseSocket(mUnixSock);
            mUnixSock = 0;
            return -1;
        }

        m_ECKeyPair.DeriveAESkey((uint8_t*)in, szOSpub);

        return 0;
    }
    catch (...) {
        return -1;
    }
}

int LocalClient::SendToLocal(Commands c, Buffer &b) {
    CommandHeader    ch;
    Buffer           send;
    int32_t          len = b.Size();
    Buffer           enc;

    if (mUnixSock == 0) {
        return -1;
    }

    try {
        enc.Clear();
        len = m_ECKeyPair.AES_Encrypt((uint8_t*)b, b.Size(), enc);
        if (len <= 0) {
            return -1;
        }

        ch.command = c;
        ch.szData = len;
        send.Append(&ch, sizeof(ch));
        send.Append(enc);

        return NonBlockingWrite(mUnixSock, send);
    }
    catch (...) {
        return -1;
    }
}

Responses LocalClient::SendToProxyPrivate(Buffer& bCmd, Buffer& out) {
    Buffer bTmp;
    char* pChar = nullptr;
    ResponseHeader* prh;

    try {
        if (mUnixSock <= 0) {
            return RSP_FILE_ERROR;
        }

        if (NonBlockingWrite(mUnixSock, bCmd) <= 0) {
            return RSP_SOCKET_IO_ERROR;
        }

        if (NonBlockingRead(mUnixSock, bTmp) <= 0) {
            return RSP_MEMORY_ERROR;
        }

        prh = (ResponseHeader*)bTmp;
        if (prh) {
            pChar = (char*)bTmp + sizeof(ResponseHeader);
            out.Clear();
            out.Append((void*)pChar, prh->szData);
            return prh->response;
        }
    }
    catch (...) {
        out.Clear();
        return RSP_INTERNAL_ERROR;
    }
   
    return RSP_INTERNAL_ERROR;
}

Responses LocalClient::SendToProxy(Buffer& bCmd, Buffer& out) {
    try {
        CommandHeader* pch = (CommandHeader*)bCmd;
        Responses r = SendToProxyPrivate(bCmd, out);
#ifndef AUTH_SERVICE
        if (pch) {
            SetCommandStatus(pch->command, r);
        }
#endif
        return r;
    }
    catch (...) {
        out.Clear();
        return RSP_INTERNAL_ERROR;
    }
}