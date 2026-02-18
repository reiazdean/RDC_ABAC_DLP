/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
Portions of this file are based on Microsoft documentation samples.
Copyright (c) Microsoft Corporation.
Used under the terms of Microsoft's documentation reuse policy.
Modifications Copyright (c) 2026 REIAZDEAN CONSULTING INC.
*/
#include "stdafx.h"
#include "Utils.h"
#include "NdacConfig.h"
#include "x509class.h"
#include "KSPkey.h"
#include "DilithiumKeyPair.h"
#include "TLSContext.h"
#include "MyKeyManager.h"
#include "SnmpTrap.h"
#include "clusterServiceManager.h"
#include "clusterClientManager.h"

#define		TABLE_SZ		65

extern Buffer* pPasswordBuffer;

uint8_t codeTable[65] =
{ 'A','B','C','D','E','F','G','H','I','J','K','L','M',
 'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
 'a','b','c','d','e','f','g','h','i','j','k','l','m',
 'n','o','p','q','r','s','t','u','v','w','x','y','z',
 '0','1','2','3','4','5','6','7','8','9','+','/','=' };

LPWORD
lpwAlign(
    LPWORD lpIn,
    ULONG dw2Power)
{
    unsigned long long ul;

    ul = (unsigned long long)lpIn;
    ul += (ul % dw2Power);
    return (LPWORD)ul;
}

uint32_t
raise(
    uint32_t base,
    uint32_t exp)
{
    uint32_t ret = 1;

    for (uint32_t i = 0; i < exp; i++) {
        ret *= base;
    }

    return ret;
}

uint32_t
ReadEncodedLength(
    FILE* fp)
{
    uint32_t     ret = 0;
    uint32_t     len;
    int     ch;

    ch = fgetc(fp);
    if ((ch & 0x80) != 0x80) {
        len = ch;
    }
    else {
        int lenOfLen = ch & 0x7F;
        if (lenOfLen > 4) {
            goto done;
        }
        len = 0;
        for (int i = lenOfLen; i > 0; i--) {
            ch = fgetc(fp);
            len += ch * raise(256, i - 1);//ch * pow((double)256, (int)(i - 1));
        }
    }

    ret = len;

done:

    return ret;
}

uint32_t
ReadMemoryEncodedLength(
    uint8_t* mem,
    uint32_t& lenOfLen)
{
    uint32_t   ret = 0;
    uint32_t   len;
    int      ch;
    uint32_t   power;

    ch = mem[0];
    if ((ch & 0x80) != 0x80) {
        len = ch;
        lenOfLen = 1;
    }
    else {
        lenOfLen = (ch & 0x7F) + 1;
        if (lenOfLen > 4) {
            goto done;
        }
        len = 0;
        power = lenOfLen - 2;
        for (uint32_t i = 0; i <= power; i++) {
            ch = mem[i + 1];
            len += ch * raise(256, power - i);
        }
    }

    ret = len;

done:

    return ret;
}


int8_t GetIndex(uint8_t b)
{
    int8_t ret = -1;
    int8_t i = 0;
    for (i = 0; i < TABLE_SZ; i++)
    {
        if (b == codeTable[i])
        {
            ret = i;
            break;
        }
    }
    return ret;
}

bool
PEM_Decode(
    Buffer& pemB,
    Buffer& derB,
    uint32_t& iSize)
{
    uint8_t  result;
    int32_t  expanded = 0;
    uint32_t  index = 0;
    uint32_t   last = iSize - 1;
    

    derB.Clear();
    try {
        char* pem = (char*)pemB;

        while (index < last)
        {
            if ((pem[index] != '\n') && (pem[index] != '\r')) {
                switch (expanded)
                {
                case 0:
                    result = (GetIndex(pem[index]) << 2) + (GetIndex(pem[index + 1]) >> 4);
                    break;
                case 1:
                    result = (GetIndex(pem[index]) << 4) + (GetIndex(pem[index + 1]) >> 2);
                    break;
                case 2:
                    result = (GetIndex(pem[index]) << 6) + (GetIndex(pem[index + 1]) >> 0);
                    index++;
                    break;
                default:
                    break;
                }
                derB.Append(&result, 1);
                expanded = (expanded + 1) % 3;
            }
            index++;
        }

        iSize = derB.Size();

        return true;
    }
    catch (...) {
        derB.Clear();
        return false;
    }
}

void
openssl_error(char* pcApi)
{
    char bErr[256];
    memset(bErr, 0, sizeof(bErr));
    ERR_error_string(ERR_get_error(), bErr);
    printf("%s: %s\n", pcApi, (char*)bErr);
}

void
init_openssl_library(void)
{
    double d = sizeof(double);
    double secs = secondsSinceNewyear();

    /* Load error strings and algorithms */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    /* Load SSL strings and initialize SSL algorithms */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    RAND_add(&secs, sizeof(secs), d);
}

char
getChar()
{
    char c;
#ifdef OS_WIN32
    c = _getch();
#else
    //taken from
    //http://www.cplusplus.com/articles/E6vU7k9E/
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    c = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
#endif
    return c;
}

int
my_cb(
    char* buf,
    int size,
    int rwflag,
    void* u)
{
    if (buf) {
        memset(buf, 0, size);
        try {
            strncpy_s(buf, size, (char*)*pPasswordBuffer, pPasswordBuffer->Size());
            buf[size - 1] = '\0';

            return (int)strlen(buf);
        }
        catch (...) {
            memset(buf, 0, size);
            return 0;
        }
    }
    return 0;
}

void
readPassword(
    char* pwdBuf,
    uint32_t szBuf)
{
    int          count = 0;
    char         c;

    memset(pwdBuf, 0, szBuf);
    do {
        c = getChar();
        pwdBuf[count] = c;
        count++;
#ifdef OS_WIN32
    } while (c != '\r' && count < MAX_PASSWD);
#else
} while (c != '\n' && count < MAX_PASSWD);
#endif
    pwdBuf[count - 1] = 0x0;
}

bool
readConsole(
    char* pcPrompt,
    char* pcOutBuf,
    uint32_t* pdwLen)
{
    bool            bRC = false;
    char            cBuf[256];

    if (!pcPrompt || !pcOutBuf)
        goto done;

    memset(cBuf, 0, sizeof(cBuf));
    printf("\nWhat is the %s: ", pcPrompt);
    fgets(cBuf, sizeof(cBuf) - 1, stdin);
    cBuf[strlen(cBuf) - 1] = 0;
    *pdwLen = (uint32_t)strlen(cBuf);
    if (*pdwLen > 0) {
        memcpy(pcOutBuf, cBuf, *pdwLen);
    }
    bRC = true;

done:

    return bRC;
}

FILE*
f_open_f(
    char* pcName,
    char* pcMode)
{
    FILE* fp = nullptr;
#ifdef OS_WIN32
    fopen_s(&fp, pcName, pcMode);
#else
    fp = fopen(pcName, pcMode);
#endif
    return fp;
}

FILE*
f_open_u(
    wchar_t* pcName,
    wchar_t* pcMode)
{
    FILE* fp = nullptr;
#ifdef OS_WIN32
    _wfopen_s(&fp, pcName, pcMode);
#else
    fp = fopen(pcName, pcMode);
#endif
    return fp;
}

bool
doTlsServerPasswordEx(
    Buffer& bPwd)
{
#ifdef AUTH_SERVICE
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
#else
    NdacClientConfig& nc = NdacClientConfig::GetInstance();
#endif
    try {
        Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);
        KSPkey ksp((WCHAR*)bKSPw);
        if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)MY_SERVER_KSP_KEY_NAME, 0)) {
            Buffer bEnc;
            Buffer bPlain;
            Buffer bFile = nc.GetValue(TLS_PRIV_KEY_PWD_FILE);
            readFile((char*)bFile, bEnc);

            if (ERROR_SUCCESS == ksp.Decrypt((uint8_t*)bEnc, bEnc.Size(), bPlain)) {
                bPlain.NullTerminate();
                bPwd = bPlain;
                return true;
            }
        }
    }
    catch (...) {
        bPwd.Clear();
        return false;
    }

    return false;
}

bool
doTlsServerPasswordSilently(
    Buffer& bPwd,
    char* pcPIN)
{
#ifdef AUTH_SERVICE
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
#else
    NdacClientConfig& nc = NdacClientConfig::GetInstance();
#endif
    try {
        Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);
        KSPkey ksp((WCHAR*)bKSPw);
        if (ERROR_SUCCESS == ksp.OpenKeySilently((WCHAR*)MY_SERVER_KSP_KEY_NAME, 0, pcPIN)) {
            Buffer bEnc;
            Buffer bPlain;
            Buffer bFile = nc.GetValue(TLS_PRIV_KEY_PWD_FILE);
            readFile((char*)bFile, bEnc);

            if (ERROR_SUCCESS == ksp.Decrypt((uint8_t*)bEnc, bEnc.Size(), bPlain)) {
                bPlain.NullTerminate();
                bPwd = bPlain;
                return true;
            }
        }
    }
    catch (...) {
        bPwd.Clear();
        return false;
    }

    return false;
}

bool
doTlsClientPasswordText(
    const char* pcPwd)
{
    FILE* fp = nullptr;
    char    buf[1024];

    if (pcPwd) {
        memset(buf, 0, sizeof(buf));
#ifdef OS_WIN32
        snprintf(buf, sizeof(buf) - 1, "%s\\.tls\\clientKey.key", "C:\\Users\\Public");// pValue);
        fopen_s(&fp, buf, "r");
#else
        snprintf(buf, sizeof(buf) - 1, "%s/.tls/clientKey.key", getenv("HOME"));
        fp = fopen(buf, "r");
#endif
        if (fp) {
            EVP_PKEY* pk = PEM_read_PrivateKey(fp, 0, my_cb, (void*)pcPwd);
            fclose(fp);
            if (pk) {
                return true;
            }
        }
    }

    return false;

}

bool
GetHostAddrInfo(
    Buffer& bIn,
    Buffer& bOut)
{
    bool bRc = false;
    int result;
    // Set up hints
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;        // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;    // TCP
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo* res = nullptr;
    const char* hostname = (char*)bIn;// "www.example.com";
    char ipstr[INET6_ADDRSTRLEN];

    // Resolve the address
    result = getaddrinfo(hostname, 0, &hints, &res);
    if (result != 0) {
        return false;
    }
    // Iterate through results
    for (struct addrinfo* ptr = res; ptr != nullptr; ptr = ptr->ai_next) {
        void* addr;
        if (ptr->ai_family == AF_INET) {  // IPv4
            sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
            addr = &(ipv4->sin_addr);
            inet_ntop(ptr->ai_family, addr, ipstr, sizeof(ipstr));
            bOut.Append((void*)ipstr, strlen(ipstr));
            bOut.NullTerminate();
            bRc = true;
            break;
        }
        else if (ptr->ai_family == AF_INET6) {  // IPv6
            sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(ptr->ai_addr);
            addr = &(ipv6->sin6_addr);
        }
        else {
            continue;
        }
    }

    freeaddrinfo(res);  // Free the linked list

    return bRc;
}

SOCKET
OpenServerInetSocket(
    int port)
{
    struct				sockaddr_in address;
    SOCKET					sock, i;

#ifdef OS_LINUX
    socklen_t addrLen = (socklen_t)sizeof(struct sockaddr_in);
#else
    int addrLen = (int)sizeof(struct sockaddr_in);
#endif

    sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&address.sin_addr, 0, sizeof(address.sin_addr));
#ifdef OS_WIN32
    //InetPton(AF_INET, (PCWSTR)"127.0.0.1", &address.sin_addr.s_addr);
    address.sin_addr.s_addr = INADDR_ANY;
#else
    address.sin_addr.s_addr = INADDR_ANY; /* all interfaces *///  inet_addr("127.0.0.1");//use inet_pton or InetPton instead
#endif
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    i = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&i, sizeof(i));

    if (bind(sock, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        CloseSocket(sock);
        return -1;
    }

    return sock;
}

SOCKET
OpenClientInetSocket(
    char* pcHost,
    int port)
{
    struct sockaddr_in address;
    SOCKET sock = -1;
    int i = -1;

    //address.sin_addr.s_addr = inet_addr("127.0.0.1");
#ifdef OS_WIN32
    InetPtonA(AF_INET, (PCSTR)pcHost, &address.sin_addr.s_addr);
#else
   // address.sin_addr.s_addr = inet_addr("127.0.0.1");//use inet_pton or InetPton instead
    inet_pton(AF_INET, (char*)pcHost, &address.sin_addr.s_addr);
#endif
    address.sin_family = AF_INET;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == 0)
        return -1;

    if (connect(sock, (struct sockaddr*)&address, sizeof(address)) == 0)
        return sock;
    else
        CloseSocket(sock);

    return -1;
}
#ifndef _OOB
void
CloseUnixSocket(
    SOCKET sock)
{
#ifdef AUTH_SERVICE
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
#else
    NdacClientConfig& nc = NdacClientConfig::GetInstance();
#endif

    if (sock > 0) {
        CloseSocket(sock);
    }

    try {
        Buffer bSockName;
        nc.GetValue(LOCAL_UNIX_SOCKET_NAME, bSockName);
        bSockName.NullTerminate();
#ifdef OS_WIN32
        _unlink((char*)bSockName);
#else
        unlink((char*)bSockName);
#endif
    }
    catch (...) {
        return;
    }
}

SOCKET
OpenUnixSocket(
    bool bServer)
{
    struct sockaddr_un addr;
    int ret;
    SOCKET sock;
    Buffer bSockName;
#ifdef AUTH_SERVICE
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
#else
    NdacClientConfig& nc = NdacClientConfig::GetInstance();
#endif

    nc.GetValue(LOCAL_UNIX_SOCKET_NAME, bSockName);
    bSockName.NullTerminate();

    /* Create local socket. */
#ifdef OS_WIN32
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
#else
    sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
#endif
    if (sock == 0) {
        return 0;
    }

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
#ifdef OS_WIN32
    strncpy_s(addr.sun_path, sizeof(addr.sun_path), (char*)bSockName, strlen((char*)bSockName));
#else
    strncpy(addr.sun_path, (char*)bSockName, strlen((char*)bSockName));
#endif

    if (bServer)
        ret = bind(sock, (const struct sockaddr*)&addr, sizeof(addr));
    else
        ret = connect(sock, (const struct sockaddr*)&addr, sizeof(addr));

    if (ret == -1) {
        CloseSocket(sock);
        return 0;
    }

    return sock;
}
#endif
int
SockRead(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess)
{
    int      r = -1;
#ifdef OS_WIN32
    r = recv(fd, pcMessIn, szMess, 0);
#else
    r = read(fd, pcMessIn, szMess);
#endif

    return r;
}

int
BlockingSockRead(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess)
{
    int r = -1;

    SetToBlock(fd);
    r = SockRead(fd, pcMessIn, szMess);
    SetToNotBlock(fd);

    return r;
}

int
SockWrite(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess)
{
    int      r = -1;
#ifdef OS_WIN32
    r = send(fd, pcMessIn, szMess, 0);
#else
    r = write(fd, pcMessIn, szMess);
#endif

    return r;
}

int
BlockingSockWrite(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess)
{
    int r = -1;
    int written = 0;
    int limit = szMess;

    SetToBlock(fd);
    do {
        int w = SockWrite(fd, pcMessIn + written, minimum(MAX_WRITE_SIZE, limit - written));
        if (w <= 0) {
            break;
        }
        written += w;
    } while (written < limit);
    SetToNotBlock(fd);

    return written;
}

int
SockReadAppend(
    SOCKET fd,
    Buffer& b)
{
    int       len = 0;
    Buffer    buff(FILE_TRANSFER_CHUNK_SZ);

    len = SockRead(fd, (char*)buff, FILE_TRANSFER_CHUNK_SZ);
    if (len > 0) {
        b.Append((void*)buff, len);
    }

    return len;
}

int
Select(
    SOCKET fd,
    int secs,
    int usecs,
    bool b_read
)
{
    fd_set fds;
    struct timeval to;
    int iFD = (int)fd;

    FD_ZERO(&fds);
    FD_SET(iFD, &fds);
    to.tv_sec = secs;
    to.tv_usec = usecs;

    return select(iFD + 1, (b_read ? &fds : 0), (b_read ? 0 : &fds), 0, (secs || usecs ? &to : 0));
}

int
BlockingRead(
    SOCKET fd,
    Buffer& b)
{
    int       len = 0;
    
    SetToBlock(fd);

    do {
        len = SockReadAppend(fd, b);
    } while (len == FILE_TRANSFER_CHUNK_SZ);

    SetToNotBlock(fd);
    
    return b.Size();
}

int
NonBlockingRead(
    SOCKET fd,
    Buffer& b,
    int timeout)
{
    int       len = 0;
    bool      retry = false;
    int       tries = 0;

    SetToNotBlock(fd);
    if (Select(fd, timeout, 0, true) < 0) {
        return -1;
    }

    if (SockReadAppend(fd, b) == 0) {
        switch (errno) {
        case EWOULDBLOCK:
            if (0 > Select(fd, 1, 0, true)) {
                return -1;
            }
            SockReadAppend(fd, b);
            break;
        case EPIPE:
        case ECONNRESET:
            CloseSocket(fd);
            return -1;
        default:
            break;
        }
    }

    return b.Size();
}

int
NonBlockingWriteEx(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess,
    int timeout)
{
    int written = 0;
    int r = 0;
    int limit = szMess;

    SetToNotBlock(fd);
    if (Select(fd, timeout, 0, false) < 0) {
        return -1;
    }

    do {
        int w = SockWrite(fd, (char*)pcMessIn + written, minimum(FILE_TRANSFER_CHUNK_SZ, limit - written));
        if (w < 0) {
            break;
        }
        written += w;
        switch (errno) {
        case EWOULDBLOCK:
            if (0 > Select(fd, 1, 0, false)) {
                return -1;
            }
            break;
        case EPIPE:
        case ECONNRESET:
            CloseSocket(fd);
            return -1;
        default:
            break;
        }
    } while (written < limit);

    return written;
}

int
NonBlockingWrite(
    SOCKET fd,
    Buffer& b,
    int timeout)
{
    try {
        return NonBlockingWriteEx(fd, (char*)b, b.Size(), timeout);
    }
    catch (...) {
        return 0;
    }
}

void
CloseSocket(SOCKET sock)
{
    if (sock <= 0) {
        return;
    }
#ifdef OS_WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

void
SetToNotBlock(SOCKET sock)
{
    if (sock <= 0) {
        return;
    }
#ifdef OS_WIN32
    int iMode = 1;
    ioctlsocket(sock, FIONBIO, (u_long FAR*) & iMode);
#else
    int arg;
    arg = fcntl(sock, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(sock, F_SETFL, arg);
#endif
}

void
SetToBlock(SOCKET sock)
{
    if (sock <= 0) {
        return;
    }
#ifdef OS_WIN32
    int iMode = 0;
    ioctlsocket(sock, FIONBIO, (u_long FAR*) & iMode);
#else
    int arg;
    arg = fcntl(sock, F_GETFL, NULL);
    arg &= (~O_NONBLOCK);
    fcntl(sock, F_SETFL, arg);
#endif
}

double
secondsSinceNewyear()
{
    time_t		now;
    time_t		then;
    struct tm	start;
    double		seconds = 0.0;

    time(&now);
#ifndef OS_WIN32
    start = *localtime(&now);
#else
    localtime_s(&start, &now);
#endif
    start.tm_hour = 0;
    start.tm_min = 0;
    start.tm_sec = 0;
    start.tm_mon = 0;
    start.tm_mday = 1;
    then = mktime(&start);
    seconds = difftime(now, then);

    return seconds;
}

int32_t
hexEncodeRaw(
    uint8_t* pcRaw,
    uint32_t szRaw,
    Buffer& bHex)
{
    char hexChars[] = "0123456789abcdef";
    if (!pcRaw)
        return 0;

    try {
        for (uint32_t i = 0; i < szRaw; i++)
        {
            char c = hexChars[pcRaw[i] >> 4];
            bHex.Append(&c, 1);
            c = hexChars[pcRaw[i] & 0x0F];
            bHex.Append(&c, 1);
        }

        return bHex.Size();
    }
    catch (...) {
        bHex.Clear();
        return 0;
    }
}

bool
hexEncode(
    uint8_t* pcRaw,
    uint32_t szRaw,
    Buffer& b)
{
    if (pcRaw) {
        try {
            Buffer bHex((size_t)szRaw * 2);
            if (hexEncodeRaw(pcRaw, szRaw, bHex) > 0) {
                b.Clear();
                b.Append(bHex);
                return true;
            }
        }
        catch (...) {
            b.Clear();
            return false;
        }
    }

    return false;
}

uint8_t
getHexIndex(uint8_t c)
{
    switch (c) {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
        return 4;
    case '5':
        return 5;
    case '6':
        return 6;
    case '7':
        return 7;
    case '8':
        return 8;
    case '9':
        return 9;
    case 'a':
    case 'A':
        return 10;
    case 'b':
    case 'B':
        return 11;
    case 'c':
    case 'C':
        return 12;
    case 'd':
    case 'D':
        return 13;
    case 'e':
    case 'E':
        return 14;
    case 'f':
    case 'F':
        return 15;
    default:
        return -1;
    }
}

uint32_t
rawDecodeHex(
    uint8_t* pcHex,
    uint32_t szHex,
    Buffer& bRaw)
{
    try {
        for (uint32_t i = 0; i < szHex; i += 2)
        {
            uint8_t  c = (getHexIndex(pcHex[i]) << 4) + getHexIndex(pcHex[i + 1]);
            bRaw.Append(&c, 1);
        }

        return bRaw.Size();
    }
    catch (...) {
        bRaw.Clear();
        return 0;
    }
}

bool
hexDecode(
    uint8_t* pcHex,
    uint32_t szHex,
    Buffer& b)
{
    if (pcHex && ((szHex % 2) == 0)) {
        try {
            Buffer bRaw(szHex / 2);
            if (rawDecodeHex(pcHex, szHex, bRaw) > 0) {
                b.Clear();
                b.Append(bRaw);
                return true;
            }
        }
        catch (...) {
            b.Clear();
            return false;
        }
    }

    return false;
}

uint8_t
saveToFile(
    int8_t* fname,
    int8_t* pcData,
    uint32_t szData)
{
    FILE* fp = NULL;
    uint8_t   bRc = 0;

    if (!fname || !pcData)
        goto done;

#ifdef OS_WIN32
    fopen_s(&fp, (char*)fname, "wb");
#else
    fp = fopen((char*)fname, "wb");
#endif
    if (fp == NULL)
        goto done;

    if (fwrite(pcData, 1, szData, fp) == szData) {
        bRc = 1;
    }

done:

    if (fp)
        fclose(fp);

    return bRc;
}



void
ReverseMemory(
    uint8_t* pbData,
    uint32_t szData)
{
    uint32_t      index;
    uint32_t      transposeIndex;
    uint8_t      bTemp;

    if (!pbData) {
        return;
    }

    for (index = 0; index < (szData / 2); index++)
    {
        transposeIndex = szData - (1 + index);

        bTemp = pbData[transposeIndex];
        pbData[transposeIndex] = pbData[index];
        pbData[index] = bTemp;
    }

    return;
}

void
stringWrite(
    int8_t* pcBuffer,
    uint32_t    lenBuffer,
    const int8_t* format,
    ...
)
{
    if (pcBuffer == NULL)
        return;
    memset(pcBuffer, 0, lenBuffer);
    va_list args;
    va_start(args, format);
#ifdef OS_WIN32
    _vsnprintf_s((char*)pcBuffer, (uint32_t)lenBuffer - 1, _TRUNCATE, (char*)format, args);
#else
    vsnprintf((char*)pcBuffer, (uint32_t)lenBuffer - 1, (char*)format, args);
#endif
    va_end(args);
}

void
stringCat(
    int8_t* pcOne,
    uint32_t   lenOne,
    int8_t* pcTwo
)
{
    if (!pcOne || !pcTwo)
        return;

#ifdef OS_WIN32
    strcat_s((char*)pcOne, (uint32_t)lenOne - 1, (char*)pcTwo);
#else
    strcat((char*)pcOne, (char*)pcTwo);
#endif

}

int8_t*
strToken(
    int8_t* pcBuf,
    const int8_t* pcSeps,
    int8_t** ppcLast
)
{
#ifdef OS_WIN32
    return (int8_t*)strtok_s((char*)pcBuf, (const char*)pcSeps, (char**)ppcLast);
#else
    return (int8_t*)strtok_r((char*)pcBuf, (char*)pcSeps, (char**)ppcLast);
#endif

}

uint32_t splitStringW(
    wchar_t* pwcString,
    wchar_t* pwcSeps,
    std::vector<wchar_t*>& pieces
)
{
    uint32_t count = 0;
    wchar_t* last = nullptr;

    if (!pwcString || !pwcSeps) {
        return 0;
    }

    wchar_t* tok = wcstok_s(pwcString, pwcSeps, &last);
    while (tok) {
        pieces.push_back(tok);
        count++;
        tok = wcstok_s(nullptr, pwcSeps, &last);
    }

    return count;
}

uint32_t splitStringA(
    char* pcString,
    char* pcSeps,
    std::vector<char*>& pieces
)
{
    uint32_t count = 0;
    char* last = nullptr;

    if (!pcString || !pcSeps) {
        return 0;
    }

    char* tok = strtok_s(pcString, pcSeps, &last);
    while (tok) {
        pieces.push_back(tok);
        count++;
        tok = strtok_s(nullptr, pcSeps, &last);
    }

    return count;
}

uint32_t ipToChars(
    int8_t* pcIP
)
{
    int8_t* token = NULL;
    int8_t* last = NULL;
    uint32_t    out = 0;
    uint8_t* pcTemp = (uint8_t*)&out;
    int32_t     i = 0;

    token = strToken(pcIP, (const int8_t*)".\r\n", &last);
    while (token && (i < sizeof(uint32_t)))
    {
        uint32_t ulVal = strtoul((char*)token, NULL, 10);

        pcTemp[i] = (uint8_t)ulVal;
        token = strToken(NULL, (const int8_t*)".\r\n", &last);
        i++;
    }

    return out;
}
void asDottedIp(
    uint32_t ip,
    Buffer& bIP
)
{
    int8_t cIP[64];
    uint8_t* pcTemp = (uint8_t*)&ip;
    try {
        memset(cIP, 0, sizeof(cIP));
        stringWrite(cIP, sizeof(cIP), (int8_t*)"%u.%u.%u.%u", pcTemp[0], pcTemp[1], pcTemp[2], pcTemp[3]);
        bIP.Append((void*)cIP, strlen((char*)cIP));
        bIP.NullTerminate();
    }
    catch (...) {
        bIP.Clear();
    }
}

uint32_t incrementIp(
    uint32_t ip
)
{
    uint32_t uTmp = ip;
    uint8_t* pcTemp = (uint8_t*)&uTmp;

    if (pcTemp[3] < 255) {
        pcTemp[3] += 1;
    }
    else {
        pcTemp[3] = 0;
        if (pcTemp[2] < 255) {
            pcTemp[2] += 1;
        }
        else {
            pcTemp[2] = 0;
            if (pcTemp[1] < 255) {
                pcTemp[1] += 1;
            }
            else {
                pcTemp[1] = 0;
                pcTemp[0] += 1;
            }
        }
    }

    return uTmp;
}

uint32_t decrementIp(
    uint32_t ip
)
{
    uint32_t uTmp = ip;
    uint8_t* pcTemp = (uint8_t*)&uTmp;

    if (pcTemp[3] > 0) {
        pcTemp[3] -= 1;
    }
    else {
        pcTemp[3] = 255;
        if (pcTemp[2] > 0) {
            pcTemp[2] -= 1;
        }
        else {
            pcTemp[2] = 255;
            if (pcTemp[1] > 0) {
                pcTemp[1] -= 1;
            }
            else {
                pcTemp[1] = 255;
                pcTemp[0] -= 1;
            }
        }
    }

    return uTmp;
}

void IncrementIp(
    const Buffer& bIPin,
    Buffer& bIPout
)
{
    try {
        Buffer bTmp = bIPin;
        uint32_t ip = ipToChars((int8_t*)bTmp);
        ip = incrementIp(ip);
        asDottedIp(ip, bIPout);
    }
    catch (...) {
        bIPout.Clear();
    }
}

void DecrementIp(
    const Buffer& bIPin,
    Buffer& bIPout
)
{
    try {
        Buffer bTmp = bIPin;
        uint32_t ip = ipToChars((int8_t*)bTmp);
        ip = decrementIp(ip);
        asDottedIp(ip, bIPout);
    }
    catch (...) {
        bIPout.Clear();
    }
}

int32_t
readFile(
    char* fname,
    Buffer& data)
{
    int32_t       ret = -1;
    FILE* fp = NULL;

#ifdef OS_WIN32
    struct _stat     buf;
    ret = _stat((char*)fname, &buf);
    if (ret == 0) {
        fopen_s(&fp, (char*)fname, "rb");
    }
#else
    struct stat     buf;
    ret = stat((char*)fname, &buf);
    if (ret == 0) {
        fp = fopen((char*)fname, "rb");
    }
#endif
    try {
        ret = 0;
        data.Clear();
        if (fp) {
            Buffer b(buf.st_size);
            ret = buf.st_size;
            if (ret == fread((char*)b, 1, ret, fp)) {
                data.Append((void*)b, ret);
            }
            fclose(fp);
            fp = NULL;
        }
    }
    catch (...) {
        if (fp) {
            fclose(fp);
        }
        data.Clear();
        return 0;
    }

    return ret;
}

int32_t
readFile_w(
    wchar_t* fname,
    Buffer& data)
{
    int32_t       ret = -1;
    FILE* fp = NULL;

#ifdef OS_WIN32
    struct _stat     buf;
    ret = _wstat(fname, &buf);
    if (ret == 0) {
        fp = f_open_u(fname, (wchar_t*)L"rb");
    }
#else
    struct stat     buf;
    ret = stat((char*)fname, &buf);
    if (ret == 0) {
        fp = fopen((char*)fname, "rb");
    }
#endif
    try {
        ret = 0;
        data.Clear();
        if (fp) {
            Buffer b(buf.st_size);
            ret = buf.st_size;
            if (ret == fread((char*)b, 1, ret, fp)) {
                data.Append((void*)b, ret);
            }
            fclose(fp);
            fp = NULL;
        }
    }
    catch (...) {
        if (fp) {
            fclose(fp);
        }
        data.Clear();
        return 0;
    }

    return ret;
}

uint32_t
Sha256(
    uint8_t* in,
    uint32_t  len,
    Buffer& out)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t* pSha = SHA256(in, len, digest);
    if (pSha) {
        try {
            out.Clear();
            if (out.Append(pSha, SHA256_DIGEST_LENGTH) == SHA256_DIGEST_LENGTH) {
                return out.Size();
            }
        }
        catch (...) {
            out.Clear();
            return 0;
        }
    }
    return 0;
}

uint32_t
Sha384(
    uint8_t* in,
    uint32_t  len,
    Buffer& out)
{
    uint8_t digest[SHA384_DIGEST_LENGTH];
    uint8_t* pSha = SHA384(in, len, digest);
    if (pSha) {
        try {
            out.Clear();
            if (out.Append(pSha, SHA384_DIGEST_LENGTH) == SHA384_DIGEST_LENGTH) {
                return out.Size();
            }
        }
        catch (...) {
            out.Clear();
            return 0;
        }
    }
    return 0;
}

uint32_t
Sha512(
    uint8_t* in,
    uint32_t  len,
    Buffer& out)
{
    uint8_t digest[SHA512_DIGEST_LENGTH];
    uint8_t* pSha = SHA512(in, len, digest);
    if (pSha) {
        try {
            out.Clear();
            if (out.Append(pSha, SHA512_DIGEST_LENGTH) == SHA512_DIGEST_LENGTH) {
                return out.Size();
            }
        }
        catch (...) {
            out.Clear();
            return 0;
        }
    }
    return 0;
}

uint32_t
AES_CBC_Encrypt(
    const uint8_t* pucKey,
    const uint8_t* pucIV,
    const uint8_t* plaintext,
    uint32_t        len,
    Buffer& bEnc)
{
    int32_t      c_len = len / AES_BLOCK_SIZE * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    int32_t      f_len = 0;
    EVP_CIPHER_CTX* ctx = 0;

    bEnc.Clear();
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), 0, pucKey, pucIV)) {
            Buffer   b(c_len);
            uint8_t* ciphertext = (uint8_t*)b;
            if (EVP_EncryptUpdate(ctx, ciphertext, &c_len, plaintext, len)) {
                if (EVP_EncryptFinal_ex(ctx, ciphertext + c_len, &f_len)) {
                    bEnc.Append((void*)b, (size_t)c_len + (size_t)f_len);
                }
            }
        }
    }
    catch (...) {
        bEnc.Clear();
    }

    EVP_CIPHER_CTX_free(ctx);
    return bEnc.Size();
}

uint32_t
AES_CBC_Decrypt(
    const uint8_t* pucKey,
    const uint8_t* pucIV,
    const uint8_t* ciphertext,
    uint32_t        len,
    Buffer& bPlain)
{
    int32_t      p_len = len + AES_BLOCK_SIZE;
    int32_t      f_len = 0;
    EVP_CIPHER_CTX* ctx = 0;

    bPlain.Clear();
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), 0, pucKey, pucIV)) {
            Buffer    b(p_len);
            uint8_t* plaintext = (uint8_t*)b;
            if (EVP_DecryptUpdate(ctx, plaintext, &p_len, ciphertext, len)) {
                if (EVP_DecryptFinal_ex(ctx, plaintext + p_len, &f_len)) {
                    bPlain.Append((void*)b, (size_t)p_len + (size_t)f_len);
                }
            }
        }
    }
    catch (...) {
        bPlain.Clear();
    }

    EVP_CIPHER_CTX_free(ctx);
    return bPlain.Size();
}

wstring
printAR(
    AuthorizationResponse* pAR
)
{
    std::wostringstream s;
    bool b = false;

    s << L"MLS=" << pAR->docMAC.mls_level << L"\n";
    s << L"MCS=";
    for (int i = 0; i < MAX_MCS_LEVEL; i++) {
        if (b && (pAR->docMAC.mcs[i] == 1)) {
            s << L",";
        }
        if (pAR->docMAC.mcs[i] == 1) {
            s << i;
            b = true;
        }
    }
    s << L"\n";
    s << L"Document Label=" << pAR->docMAC.mls_desc;
    for (int i = 0; i < MAX_MCS_LEVEL; i++) {
        if (pAR->docMAC.mcs[i] == 1)
            s << L"," << pAR->docMAC.mcs_desc[i];
    }
    s << L"\n";
    s << L"HsmKeyName=" << pAR->hsmKeyName;
    s << L"\n";

    return s.str();
}

uint32_t
RSA_Encrypt(
    wchar_t* pcCertFile,
    uint8_t* plain,
    uint32_t szPlain,
    Buffer& bEnc)
{
    FILE* fp = nullptr;
    X509* cert = nullptr;
    EVP_PKEY* pubkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    size_t outlen = 0;

    bEnc.Clear();

    fp = f_open_u(pcCertFile, (wchar_t*)L"r");
    if (!fp)
        goto done;

    cert = PEM_read_X509(fp, 0, 0, 0);
    if (!cert)
        goto done;

    pubkey = X509_get_pubkey(cert);
    if (!pubkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(pubkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto done;

    try {
        if (EVP_PKEY_encrypt(ctx, 0, &outlen, plain, szPlain)) {
            Buffer b(outlen);

            if (EVP_PKEY_encrypt(ctx, (uint8_t*)b, &outlen, plain, szPlain)) {
                bEnc.Append((uint8_t*)b, outlen);
            }
        }
    }
    catch (...) {
        bEnc.Clear();
    }

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (pubkey)
        EVP_PKEY_free(pubkey);

    if (cert)
        X509_free(cert);

    if (fp)
        fclose(fp);

    return bEnc.Size();
}

uint32_t
RSA_Decrypt(
    wchar_t* pcPrivKeyFile,
    uint8_t* enc,
    uint32_t szEnc,
    uint8_t* pcPasswd,
    Buffer& bPlain)
{
    FILE* fp = nullptr;
    EVP_PKEY* privkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    size_t            outlen;

    bPlain.Clear();

    fp = f_open_u(pcPrivKeyFile, (wchar_t*)L"r");
    if (!fp)
        goto done;

    privkey = PEM_read_PrivateKey(fp, 0, 0, (void*)pcPasswd);
    if (!privkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(privkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto done;

    try {
        if (EVP_PKEY_decrypt(ctx, 0, &outlen, enc, szEnc)) {
            Buffer b(outlen);
            if (EVP_PKEY_decrypt(ctx, (uint8_t*)b, &outlen, enc, szEnc))
            {
                bPlain.Append((uint8_t*)b, outlen);
            }
        }
    }
    catch (...) {
        bPlain.Clear();
    }

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (privkey)
        EVP_PKEY_free(privkey);

    if (fp)
        fclose(fp);

    return bPlain.Size();
}

uint32_t
RSA_PubKey_Encrypt(
    EVP_PKEY* pubkey,
    uint8_t* plain,
    uint32_t szPlain,
    Buffer& bEnc)
{
    EVP_PKEY_CTX* ctx = nullptr;
    size_t outlen = 0;

    bEnc.Clear();

    ctx = EVP_PKEY_CTX_new(pubkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto done;

    try {
        if (EVP_PKEY_encrypt(ctx, 0, &outlen, plain, szPlain)) {
            Buffer b(outlen);

            if (EVP_PKEY_encrypt(ctx, (uint8_t*)b, &outlen, plain, szPlain)) {
                bEnc.Append((uint8_t*)b, outlen);
                //LogBinary((uint8_t*)"sdas:\n", (uint8_t*)b, outlen);
            }
            else {
                openssl_error((char*)"EVP_PKEY_encrypt");
            }
        }
    }
    catch (...) {
        bEnc.Clear();
    }

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return bEnc.Size();
}

uint32_t
RSA_Sign(
    wchar_t* pcPrivKeyFile,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* pcPasswd,
    Buffer& bSignature)
{
    FILE* fp = nullptr;
    EVP_PKEY* privkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    size_t  outlen;

    bSignature.Clear();

    if (!pcPrivKeyFile)
        goto done;

    fp = f_open_u(pcPrivKeyFile, (wchar_t*)L"r");
    if (!fp)
        goto done;

    privkey = PEM_read_PrivateKey(fp, 0, 0, (void*)pcPasswd);
    if (!privkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(privkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_sign_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;

    if (szHash == SHA256_DIGEST_LENGTH) {
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
            goto done;
    }
    else if (szHash == SHA384_DIGEST_LENGTH) {
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()) <= 0)
            goto done;
    }
    else if (szHash == SHA512_DIGEST_LENGTH) {
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) <= 0)
            goto done;
    }
    else {
        goto done;
    }

    try {
        if (EVP_PKEY_sign(ctx, 0, &outlen, hash, szHash)) {
            Buffer b(outlen);
            if (EVP_PKEY_sign(ctx, (uint8_t*)b, &outlen, hash, szHash))
            {
                bSignature.Append((uint8_t*)b, outlen);
            }
        }
    }
    catch (...) {
        bSignature.Clear();
    }

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (privkey)
        EVP_PKEY_free(privkey);

    if (fp)
        fclose(fp);

    return bSignature.Size();
}

bool
RSA_Verify(
    wchar_t* pcCertFile,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature)
{
    EVP_PKEY* pubkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    FILE* fp = nullptr;
    X509* cert = nullptr;
    int32_t           ret = 0;

    if (pcCertFile) {
        fp = f_open_u(pcCertFile, (wchar_t*)L"r");
    }
    if (!fp)
        goto done;

    cert = PEM_read_X509(fp, 0, 0, 0);
    if (!cert)
        goto done;

    pubkey = X509_get_pubkey(cert);
    if (!pubkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(pubkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;

    if (szHash == SHA256_DIGEST_LENGTH) {
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
            goto done;
    }
    else if (szHash == SHA384_DIGEST_LENGTH) {
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()) <= 0)
            goto done;
    }
    else if (szHash == SHA512_DIGEST_LENGTH) {
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) <= 0)
            goto done;
    }
    else {
        goto done;
    }

    ret = EVP_PKEY_verify(ctx, signature, szSignature, hash, szHash);
    if (ret != 1) {
        openssl_error((char*)"EVP_PKEY_verify");
    }

done:

    if (cert)
        X509_free(cert);

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (pubkey)
        EVP_PKEY_free(pubkey);

    if (fp)
        fclose(fp);

    return (ret == 1);
}

std::shared_ptr<RSAPublicKey>
CreateRSAPublicKeyCNG(Buffer bCert)
{
    uint32_t sz = 0;
    std::shared_ptr<RSAPublicKey> pRSA = nullptr;
    try {
        Buffer bPK;
        SequenceReaderX	seq;
        Certificate ca(bCert);
        ca.GetPublicKeyInfo(bPK);

        if (seq.Initilaize(bPK)) {
            Buffer bPubKey;
            Buffer bTemp;
            SequenceReaderX s2;
            if (seq.getValueAt(1, bTemp)) {
                uint8_t* p = (uint8_t*)bTemp;
                sz = bTemp.Size();
                if (p[0] == 0) {//ASN BIT STRINGS(0x03) MUST CARRY A UNUSED BITS BYTE. THIS MUST BE ZERO FOR RSA VALUES
                    p++;
                    sz--;
                }
                bPubKey.Append(p, sz);
            }
            if (s2.Initilaize(bPubKey)) {
                BCRYPT_RSAKEY_BLOB pubBlob = { BCRYPT_RSAPUBLIC_MAGIC, 2048, 0, 0, 0, 0 };
                Buffer bMod, bExp;
                if (!s2.getValueAt(0, bMod)) {
                    return nullptr;
                }
                if (!s2.getValueAt(1, bExp)) {
                    return nullptr;
                }
                pubBlob.cbModulus = bMod.Size();
                pubBlob.cbPublicExp = bExp.Size();
                bPubKey.Clear();
                bPubKey.Append((void*)&pubBlob, sizeof(BCRYPT_RSAKEY_BLOB));
                bPubKey.Append(bExp);
                bPubKey.Append(bMod);
                pRSA = std::make_shared<RSAPublicKey>((uint8_t*)bPubKey, bPubKey.Size());
            }
        }
    }
    catch (...) {
        pRSA = nullptr;
    }

    return pRSA;
}

int
VerifySignatureCNG(
    Buffer bCert,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature
)
{
    bool bRc = false;
    BCRYPT_PKCS1_PADDING_INFO pi;
    std::shared_ptr<RSAPublicKey> pRSA = CreateRSAPublicKeyCNG(bCert);
    if (pRSA) {
        pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        if (ERROR_SUCCESS == pRSA->VerifySignature(&pi, hash, szHash, signature, szSignature, BCRYPT_PAD_PKCS1)) {
            return 1;
        }
    }
    return -1;
}

bool
RSA_VerifyBIO(
    uint8_t* pcCertData,
    uint32_t szCertData,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature)
{
    EVP_PKEY* pubkey = nullptr;
    BIO* bio = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    X509* cert = nullptr;;
    int32_t           ret = 0;

    // DER encoded pcCertData
    cert = d2i_X509(&cert, (const unsigned char**)&pcCertData, szCertData);
    if (!cert) {
        goto done;
    }

    pubkey = X509_get_pubkey(cert);
    if (!pubkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(pubkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    ret = EVP_PKEY_verify(ctx, signature, szSignature, hash, szHash);
    if (ret == 0) {
        openssl_error((char*)"EVP_PKEY_verify");
    }

done:

    if (cert)
        X509_free(cert);

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (pubkey)
        EVP_PKEY_free(pubkey);

    if (bio)
        BIO_free(bio);

    return (ret == 1);
}

bool
RSA_VerifyDER(
    uint8_t* pcCertData,
    uint32_t szCertData,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature
)
{
    EVP_PKEY* pubkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    X509* cert = nullptr;
    int32_t       ret = 0;

    cert = d2i_X509(&cert, (const unsigned char**)&pcCertData, szCertData);
    if (!cert)
        goto done;

    pubkey = X509_get_pubkey(cert);
    if (!pubkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(pubkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    ret = EVP_PKEY_verify(ctx, signature, szSignature, hash, szHash);

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (pubkey)
        EVP_PKEY_free(pubkey);

    if (cert)
        X509_free(cert);


    return (ret == 1);
}

bool
VerifyPEMCertWithBundle(
    const char* pcBundleFile,
    const char* pcCertData,
    uint32_t szCertData)
{
    bool            bRc = false;
    BIO* certbio = NULL;
    X509* cert = NULL;
    X509_STORE* certstore = NULL;
    X509_STORE_CTX* verify_ctx = NULL;
    int ret;

    // Create a read-only BIO backed by the supplied memory buffer
    certbio = BIO_new_mem_buf((void*)pcCertData, szCertData);
    cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    if (!cert) {
        goto done;
    }

    certstore = X509_STORE_new();
    if (!certstore) {
        goto done;
    }

    verify_ctx = X509_STORE_CTX_new();

    ret = X509_STORE_load_file(certstore, pcBundleFile);//X509_STORE_load_locations(certstore, pcBundleFile, NULL);
    if (ret != 1) {
        goto done;
    }

    X509_STORE_CTX_init(verify_ctx, certstore, cert, NULL);
    ret = X509_verify_cert(verify_ctx);
    bRc = (ret == 1);

    if (bRc) {
        STACK_OF(X509)* certs = X509_STORE_CTX_get1_chain(verify_ctx);
        for (int i = 0; i < sk_X509_num(certs); i++) {
            char    name[2048];
            int     name_len = 0;
            X509* x509 = sk_X509_value(certs, i);
            X509_NAME* subj = X509_get_subject_name(x509);
            memset(name, 0, sizeof(name));
            name_len = X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name));
        }
    }

done:

    if (verify_ctx) {
        X509_STORE_CTX_free(verify_ctx);
    }
    if (certstore) {
        X509_STORE_free(certstore);
    }
    if (cert) {
        X509_free(cert);
    }
    if (certbio) {
        BIO_free_all(certbio);
    }

    return bRc;
}

bool
VerifyCertWithBundle(
    char* pcBundleFile,
    const uint8_t* pcCertData,
    uint32_t szCertData)
{
    bool bRc = false;
    X509* cert = NULL;
    X509_STORE* certstore = NULL;
    X509_STORE_CTX* verify_ctx = NULL;

    const unsigned char* p = (const unsigned char*)pcCertData;
    cert = d2i_X509(NULL, &p, szCertData);
    //cert = d2i_X509(&cert, &pcCertData, szCertData);
    if (cert) {
        certstore = X509_STORE_new();
        if (certstore) {
            verify_ctx = X509_STORE_CTX_new();
            if (verify_ctx) {
                if (1 == X509_STORE_load_locations(certstore, (char*)pcBundleFile, 0)) {//X509_STORE_load_file(certstore, pcBundleFile);
                    if (1 == X509_STORE_CTX_init(verify_ctx, certstore, cert, NULL)) {
                        bRc = (1 == X509_verify_cert(verify_ctx));
                    }
                }
            }
        }
    }


    if (bRc) {
        STACK_OF(X509)* certs = X509_STORE_CTX_get1_chain(verify_ctx);
        for (int i = 0; i < sk_X509_num(certs); i++) {
            char    name[2048];
            int     name_len = 0;
            X509* x509 = sk_X509_value(certs, i);
            if (x509) {
                X509_NAME* subj = X509_get_subject_name(x509);
                if (subj) {
                    memset(name, 0, sizeof(name));
                    name_len = X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name));
                }
            }
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (!bRc) {
        if (X509_V_ERR_CERT_HAS_EXPIRED == X509_STORE_CTX_get_error(verify_ctx)) {
            bRc = true;
        }
    }

    if (verify_ctx) {
        X509_STORE_CTX_free(verify_ctx);
    }
    if (certstore) {
        X509_STORE_free(certstore);
    }
    if (cert) {
        X509_free(cert);
    }

    return bRc;
}

bool
VerifyCertRequestFile(
    const char* pcRequestFile)
{
    int r = -1;
    X509_REQ* req = NULL;
    FILE* fp = NULL;
#ifdef OS_WIN32
    fopen_s(&fp, (char*)pcRequestFile, "r");
#else
    fp = fopen((char*)pcRequestFile, "r");
#endif

    if (fp) {
        req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
        if (req) {
            EVP_PKEY* pkey = X509_REQ_get0_pubkey(req);
            if (pkey) {
                r = X509_REQ_verify(req, pkey);
                EVP_PKEY_free(pkey);
            }
            //EVP_REQ_free(req);
        }
        fclose(fp);
    }

    return (r == 1);
}

uint32_t
RSA_PubKey_Decrypt(
    uint8_t* enc,
    uint32_t szEnc,
    Buffer& bPlain,
    uint8_t* pcCertFile)
{
    FILE* fp = nullptr;
    EVP_PKEY* pubkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    size_t            outlen;
    X509* cert;

    bPlain.Clear();

#ifdef OS_WIN32
    fopen_s(&fp, (char*)pcCertFile, "r");
#else
    fp = fopen((char*)pcCertFile, "r");
#endif

    if (!fp)
        goto done;

    cert = PEM_read_X509(fp, 0, 0, 0);
    if (!cert)
        goto done;

    pubkey = X509_get_pubkey(cert);
    if (!pubkey)
        goto done;

    ctx = EVP_PKEY_CTX_new(pubkey, 0);
    if (!ctx)
        goto done;

    if (EVP_PKEY_verify_recover_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;

    try {
        if (EVP_PKEY_verify_recover(ctx, 0, &outlen, enc, szEnc)) {
            Buffer b(outlen);
            if (EVP_PKEY_verify_recover(ctx, (uint8_t*)b, &outlen, enc, szEnc) <= 0)
            {
                bPlain.Append((uint8_t*)b, outlen);
            }
        }
    }
    catch (...) {
        bPlain.Clear();
    }

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (pubkey)
        EVP_PKEY_free(pubkey);

    if (fp)
        fclose(fp);

    return bPlain.Size();
}

bool
PEMcert_to_DERcert(
    Buffer& cert,
    uint32_t& sz)
{
    bool bRc = false;
    try {
        if (cert.Size() > 0) {
            char* pCert = (char*)cert;
            char* pcTmp = nullptr;
            char* pcBegin = strstr(pCert, (char*)"-----BEGIN CERTIFICATE-----");
            char* pcEnd = strstr(pCert, (char*)"-----END CERTIFICATE-----");

            if (!pcBegin || !pcEnd) {
                return false;
            }

            if (pcBegin >= pcEnd) {
                return false;
            }

            pcTmp = pcEnd;
            if (pcTmp) {
                Buffer pem;
                Buffer der;
                
                pcTmp[0] = 0;
                pcTmp = pCert + strlen((char*)"-----BEGIN CERTIFICATE-----");
                sz = (uint32_t)strlen(pcTmp);
                pem.Append(pcTmp, sz);
                if (PEM_Decode(pem, der, sz)) {
                    Certificate x509(der);
                    if (x509.IsValid()) {
                        cert.Clear();
                        cert.Append((uint8_t*)der, sz);
                        return true;
                    }
                }
            }
        }
    }
    catch (...) {
        cert.Clear();
        sz = 0;
        return false;
    }

    return false;
}

int
CertFileType(
    char* pcCertFile
)
{
    try {
        Buffer cert;

        if (pcCertFile) {
            readFile(pcCertFile, cert);
        }

        if (cert.Size() > 0) {
            char* pCert = (char*)cert;
            if (pCert) {
                if (pCert[0] == CONSTRUCTED_SEQUENCE) {
                    Certificate c(cert);
                    if (c.IsValid()) {
                        return CERT_FILE_TYPE_DER;
                    }
                }
                else if (strstr(pCert, (char*)"-----BEGIN CERTIFICATE-----")) {
                    return CERT_FILE_TYPE_PEM;
                }
            }
        }
    }
    catch (...) {
        return CERT_FILE_TYPE_UNK;
    }

    return CERT_FILE_TYPE_UNK;
}

void
LogBinary(
    FILE* fp,
    uint8_t* label,
    uint8_t* data,
    uint32_t len)
{
    unsigned long i;

    if (!label || !data || !len)
        return;

    fprintf(fp, "%s\n", label);
    for (i = 1; i < len + 1; i++) {
        fprintf(fp, "%02X ", data[i - 1]);
        if ((i % 16) == 0) fprintf(fp, "\r\n");
    }
    if ((i % 16) != 0) fprintf(fp, "\r\n");
    fprintf(fp, "\n\n");
}

#ifdef OS_WIN32
//https://learn.microsoft.com/en-us/windows/win32/fileio/listing-the-files-in-a-directory
int
GetDirectoryContents(
    wchar_t* dirName,
    Buffer& b)
{
    WIN32_FIND_DATAW ffd;
    wchar_t szDir[MAX_LINE];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    int count = 0;

    try {
        b.Clear();
        // Check that the input path plus 3 is not longer than MAX_LINE.
        // Three characters are for the "\*" plus NULL appended below.
        if (FAILED(StringCchLengthW(dirName, MAX_LINE, &length_of_arg))) {
            return 0;
        }
        if (length_of_arg > (MAX_LINE - 3)) {
            return 0;
        }
        // Prepare string for use with FindFile functions.  First, copy the
        // string to a buffer, then append '\*' to the directory name.
        if (FAILED(StringCchCopyW(szDir, MAX_LINE, dirName))) {
            return 0;
        }
        if (FAILED(StringCchCatW(szDir, MAX_LINE, L"\\*"))) {
            return 0;
        }
        // Find the first file in the directory.
        hFind = FindFirstFileW(szDir, &ffd);
        if (INVALID_HANDLE_VALUE == hFind) {
            return 0;
        }
        // List all the files in the directory with some info about them.
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                size_t szfn = 0;
                if (SUCCEEDED(StringCbLengthW(ffd.cFileName, MAX_LINE, &szfn))) {
                    if (wcscmp(L"LockFile.lck", ffd.cFileName) != 0) {
                        if (!wcsstr((WCHAR*)ffd.cFileName, L".declassified")) {
                            if (!wcsstr((WCHAR*)ffd.cFileName, L".published")) {
                                b.Append((void*)ffd.cFileName, szfn);
                                b.EOLN_w();
                                count++;
                            }
                        }
                    }
                }
            }
        } while (FindNextFileW(hFind, &ffd) != 0);
        b.NullTerminate_w();
        //finish
        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
        return count;
    }
    catch (...) {
        if (INVALID_HANDLE_VALUE != hFind) {
            FindClose(hFind);
        }
        b.Clear();
        return 0;
    }
}

int
GetDirectoryContentsWithExtension(
    wchar_t* dirName,
    wchar_t* ext,
    Buffer& b)
{
    WIN32_FIND_DATAW ffd;
    wchar_t szDir[MAX_LINE];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    int count = 0;

    try {
        // Check that the input path plus 3 is not longer than MAX_LINE.
        // Three characters are for the "\*" plus NULL appended below.
        if (FAILED(StringCchLengthW(dirName, MAX_LINE, &length_of_arg))) {
            return 0;
        }
        if (length_of_arg > (MAX_LINE - 5)) {
            return 0;
        }
        // Prepare string for use with FindFile functions.  First, copy the
        // string to a buffer, then append '\*' to the directory name.
        if (FAILED(StringCchCopyW(szDir, MAX_LINE, dirName))) {
            return 0;
        }
        if (FAILED(StringCchCatW(szDir, MAX_LINE, ext))) {
            return 0;
        }
        // Find the first file in the directory.
        hFind = FindFirstFileW(szDir, &ffd);
        if (INVALID_HANDLE_VALUE == hFind) {
            return 0;
        }
        // List all the files in the directory with some info about them.
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                size_t szfn = 0;
                if (SUCCEEDED(StringCbLengthW(ffd.cFileName, MAX_LINE, &szfn))) {
                    b.Append((void*)dirName, wcslen(dirName) * sizeof(WCHAR));
                    b.Append((void*)L"\\", sizeof(WCHAR));
                    b.Append((void*)ffd.cFileName, szfn);
                    b.EOLN_w();
                    count++;
                }
            }
        } while (FindNextFileW(hFind, &ffd) != 0);

        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
        return count;
    }
    catch (...) {
        if (INVALID_HANDLE_VALUE != hFind) {
            FindClose(hFind);
        }
        return 0;
    }
}


int
GetSubDirectories(
    wchar_t* dirName,
    Buffer& b)
{
    WIN32_FIND_DATAW ffd;
    wchar_t szDir[MAX_LINE];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    int count = 0;

    try {
        b.Clear();
        // Check that the input path plus 3 is not longer than MAX_LINE.
        // Three characters are for the "\*" plus NULL appended below.
        if (FAILED(StringCchLengthW(dirName, MAX_LINE, &length_of_arg))) {
            return 0;
        }
        if (length_of_arg > (MAX_LINE - 3))
        {
            return 0;
        }
        // Prepare string for use with FindFile functions.  First, copy the
        // string to a buffer, then append '\*' to the directory name.
        if (FAILED(StringCchCopyW(szDir, MAX_LINE, dirName))) {
            return 0;
        }
        if (FAILED(StringCchCatW(szDir, MAX_LINE, L"\\*"))) {
            return 0;
        }
        // Find the first file in the directory.
        hFind = FindFirstFileW(szDir, &ffd);
        if (INVALID_HANDLE_VALUE == hFind)
        {
            return 0;
        }
        // List all the files in the directory with some info about them.
        do {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if ((wcscmp(ffd.cFileName, L".") != 0) && (wcscmp(ffd.cFileName, L"..") != 0)) {
                    size_t szfn = 0;
                    if (SUCCEEDED(StringCbLengthW(ffd.cFileName, MAX_LINE, &szfn))) {
                        b.Append((void*)ffd.cFileName, szfn);
                        b.EOLN_w();
                        count++;
                    }
                }
            }
        } while (FindNextFileW(hFind, &ffd) != 0);
        b.NullTerminate_w();
        //finish
        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
        return count;
    }
    catch (...) {
        if (INVALID_HANDLE_VALUE != hFind) {
            FindClose(hFind);
        }
        b.Clear();
        return 0;
    }
}

int
GetDirectoryTree(
    wchar_t* dirName,
    Buffer& b,
    int level)
{
    WIN32_FIND_DATAW ffd;
    wchar_t szDir[MAX_LINE];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    wchar_t start[16] = L"<DIR>\n";
    size_t szStart = 0;
    wchar_t end[16] = L"</DIR>\n";
    size_t szEnd = 0;

    try {
        if (FAILED(StringCbLengthW(start, 16, &szStart)) ||
            FAILED(StringCbLengthW(end, 16, &szEnd))) {
            return 0;
        }

        // Check that the input path plus 3 is not longer than MAX_LINE.
        // Three characters are for the "\*" plus NULL appended below.
        if (FAILED(StringCchLengthW(dirName, MAX_LINE, &length_of_arg))) {
            return 0;
        }
        if (length_of_arg > (MAX_LINE - 3))
        {
            return 0;
        }
        // Prepare string for use with FindFile functions.  First, copy the
        // string to a buffer, then append '\*' to the directory name.
        if (FAILED(StringCchCopyW(szDir, MAX_LINE, dirName))) {
            return 0;
        }
        if (FAILED(StringCchCatW(szDir, MAX_LINE, L"\\*"))) {
            return 0;
        }
        // Find the first file in the directory.
        hFind = FindFirstFileW(szDir, &ffd);
        if (INVALID_HANDLE_VALUE == hFind) {
            return 0;
        }
        // List all the files in the directory with some info about them.
        do {
            if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                int i = 0;
                wchar_t c = L'.';

                if (ffd.cFileName[0] != c) {
                    wchar_t szNewDir[MAX_LINE];
                    size_t sz = 0;

                    if (SUCCEEDED(StringCbLengthW(ffd.cFileName, MAX_LINE, &sz)) &&
                        SUCCEEDED(StringCchCopyW(szNewDir, MAX_LINE, dirName)) &&
                        SUCCEEDED(StringCchCatW(szNewDir, MAX_LINE, L"\\")) &&
                        SUCCEEDED(StringCchCatW(szNewDir, MAX_LINE, ffd.cFileName))) {
                        for (i = 0; i < level; i++) {
                            b.Tab_w();
                        }
                        b.Append((void*)start, szStart);
                        for (i = 0; i < level; i++) {
                            b.Tab_w();
                        }
                        b.Append((void*)ffd.cFileName, sz);
                        b.EOLN_w();
                        GetDirectoryTree(szNewDir, b, level + 1);
                        for (i = 0; i < level; i++) {
                            b.Tab_w();
                        }
                        b.Append((void*)end, szEnd);
                    }
                }
            }
        } while (FindNextFileW(hFind, &ffd) != 0);
        //finish
        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }
    catch (...) {
        if (INVALID_HANDLE_VALUE != hFind) {
            FindClose(hFind);
        }
        b.Clear();
        return -1;
    }

    return 0;
}

bool
IsValidMCSFolder(
    wchar_t* path,
    wchar_t* dirName,
    int level,
    Mandatory_AC& userMac)
{
    try {
        Buffer bFolder;
        wchar_t c = L'.';
        if (!dirName) {
            return false;
        }

        if (dirName[0] == c) {
            return false;
        }

        if (wcscmp(dirName, L"Temp") == 0) {
            return false;
        }

        if (wcscmp(dirName, L"ClusterConfigs") == 0) {
            return false;
        }

        if (level != 2) {
            return true;
        }
        //else if (wcsstr(path, L"\\Declassified\\")) {
            //return true;
        //}

        GetUtf8FromWchar(dirName, bFolder);
        bFolder.NullTerminate();

        for (int i = 0; i < MAX_MCS_LEVEL; i++) {
            if (strcmp((char*)bFolder, userMac.mcs_desc[i]) == 0) {
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
IsValidMLSFolder(
    wchar_t* path,
    wchar_t* dirName,
    int level,
    Mandatory_AC& userMac)
{
    try {
        Buffer bFolder;
        wchar_t c = L'.';
        if (!dirName) {
            return false;
        }

        if (dirName[0] == c) {
            return false;
        }

        if (level != 3) {
            return true;
        }
        else if (wcsstr(path, L"\\Declassified\\")) {
            return true;
        }

        GetUtf8FromWchar(dirName, bFolder);
        bFolder.NullTerminate();

        for (int i = 0; i < MAX_MLS_LEVEL; i++) {
            if (strcmp((char*)bFolder, userMac.implied_mls_desc[i]) == 0) {
                return true;
            }
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

int
GetFilteredDirectoryTree(
    wchar_t* dirName,
    Buffer& b,
    Mandatory_AC& userMac,
    int level)
{
    WIN32_FIND_DATAW ffd;
    wchar_t szDir[MAX_LINE];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    wchar_t start[16] = L"<DIR>\n";
    size_t szStart = 0;
    wchar_t end[16] = L"</DIR>\n";
    size_t szEnd = 0;

    try {
        if (FAILED(StringCbLengthW(start, 16, &szStart)) ||
            FAILED(StringCbLengthW(end, 16, &szEnd))) {
            return 0;
        }

        // Check that the input path plus 3 is not longer than MAX_LINE.
        // Three characters are for the "\*" plus NULL appended below.
        if (FAILED(StringCchLengthW(dirName, MAX_LINE, &length_of_arg))) {
            return 0;
        }
        if (length_of_arg > (MAX_LINE - 3))
        {
            return 0;
        }
        // Prepare string for use with FindFile functions.  First, copy the
        // string to a buffer, then append '\*' to the directory name.
        if (FAILED(StringCchCopyW(szDir, MAX_LINE, dirName))) {
            return 0;
        }
        if (FAILED(StringCchCatW(szDir, MAX_LINE, L"\\*"))) {
            return 0;
        }
        // Find the first file in the directory.
        hFind = FindFirstFileW(szDir, &ffd);
        if (INVALID_HANDLE_VALUE == hFind) {
            return 0;
        }
        // List all the files in the directory with some info about them.
        do {
            if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                int i = 0;
                
                if (IsValidMCSFolder(szDir, ffd.cFileName, level, userMac) && IsValidMLSFolder(szDir, ffd.cFileName, level, userMac)) {
                    wchar_t szNewDir[MAX_LINE];
                    size_t sz = 0;

                    if (SUCCEEDED(StringCbLengthW(ffd.cFileName, MAX_LINE, &sz)) &&
                        SUCCEEDED(StringCchCopyW(szNewDir, MAX_LINE, dirName)) &&
                        SUCCEEDED(StringCchCatW(szNewDir, MAX_LINE, L"\\")) &&
                        SUCCEEDED(StringCchCatW(szNewDir, MAX_LINE, ffd.cFileName))) {
                        for (i = 0; i < level; i++) {
                            b.Tab_w();
                        }
                        b.Append((void*)start, szStart);
                        for (i = 0; i < level; i++) {
                            b.Tab_w();
                        }
                        b.Append((void*)ffd.cFileName, sz);
                        b.EOLN_w();
                        GetFilteredDirectoryTree(szNewDir, b, userMac, level + 1);
                        for (i = 0; i < level; i++) {
                            b.Tab_w();
                        }
                        b.Append((void*)end, szEnd);
                    }
                }
            }
        } while (FindNextFileW(hFind, &ffd) != 0);
        //finish
        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }
    catch (...) {
        if (INVALID_HANDLE_VALUE != hFind) {
            FindClose(hFind);
        }
        b.Clear();
        return -1;
    }

    return 0;
}

char*
GetUtf8FromWchar(
    const wchar_t* pwcTemp,
    Buffer& b)
{
    int ulLen = 0;
    if (!pwcTemp)
        return 0;

    try {
        ulLen = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS * 0, pwcTemp, (int)wcslen(pwcTemp), NULL, 0, NULL, NULL);
        if (ulLen > 0) {
            Buffer c((size_t)ulLen + 1);
            ulLen = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS * 0, pwcTemp, (int)wcslen(pwcTemp),
                (char*)c, ulLen + 1, NULL, NULL);
            b.Append((void*)c, ulLen);
            b.NullTerminate();
        }

        return (char*)b;
    }
    catch (...) {
        b.Clear();
        return 0;
    }
}

wchar_t*
GetWcharFromUtf8(
    const char* pcUtf8,
    Buffer& b)
{
    int ulLen = 0;
    Buffer c;

    if (!pcUtf8)
        return 0;

    try {
        ulLen = MultiByteToWideChar(CP_UTF8, 0, pcUtf8, (int)strlen(pcUtf8), NULL, 0);
        if (ulLen > 0) {
            int32_t sz = (ulLen + 1) * sizeof(WCHAR);
            Buffer c(sz);
            ulLen = MultiByteToWideChar(CP_UTF8, 0, pcUtf8, (int)strlen(pcUtf8), (WCHAR*)c, ulLen + 1);
            b.Append((void*)c, sz);
        }

        return (WCHAR*)b;
    }
    catch (...) {
        b.Clear();
        return 0;
    }
}

#endif

time_t
FromUTC(
    uint8_t* pbData,
    uint32_t dwLen)
{
    struct tm		t;
    char			cBuf[3];
    int				offset = 0;

    if (pbData == NULL)
        return 0;
    if (dwLen != 13)
        return 0;
    if (pbData[12] != 'Z')
        return 0;

    cBuf[2] = 0;
    memset(&t, 0, sizeof(struct tm));

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_year = atoi(cBuf);
    if (t.tm_year < 50)
        t.tm_year += 100;

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_mon = atoi(cBuf) - 1;

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_mday = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_hour = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_min = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_sec = atoi(cBuf);

    return mktime(&t);

}

time_t
FromGeneralized(
    uint8_t* pbData,
    uint32_t dwLen)
{
    struct tm		t;
    char			cBuf[3];
    int				offset = 0;
    int				centuary = 0;

    if (pbData == NULL)
        return 0;
    if (dwLen != 15)
        return 0;
    if (pbData[14] != 'Z')
        return 0;

    cBuf[2] = 0;
    memset(&t, 0, sizeof(struct tm));

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    centuary = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_year = atoi(cBuf);
    t.tm_year = centuary * 100 + t.tm_year - 1900;

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_mon = atoi(cBuf) - 1;

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_mday = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_hour = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_min = atoi(cBuf);

    memcpy(cBuf, pbData + offset, 2);
    offset += 2;
    t.tm_sec = atoi(cBuf);

    return mktime(&t);

}

time_t
AsTime_t(
    Buffer& obj)
{
    uint32_t    dwLen = 0;
    uint32_t    dwPos = 0;

    try {
        if (SequenceReaderX::ReadLengthValue((uint8_t*)obj, &dwLen, &dwPos)) {
            if ((dwLen + dwPos) == obj.Size()) {
                if (obj[0] == UNIVERSAL_TYPE_DATE1)
                    return FromUTC((uint8_t*)obj + dwPos, dwLen);
                else if (obj[0] == UNIVERSAL_TYPE_DATE2)
                    return FromGeneralized((uint8_t*)obj + dwPos, dwLen);
            }
        }
    }
    catch (...) {
        return 0;
    }

    return 0;
}

bool
KSPGetUserCertificate(
    WCHAR* pwcKeyName,
    Buffer& bCert)
{
    try {
        if (pwcKeyName) {
            KSPkey ksp((WCHAR*)L"Microsoft Smart Card Key Storage Provider");
            if (ERROR_SUCCESS == ksp.OpenKey(pwcKeyName, AT_SIGNATURE)) {
                if (ERROR_SUCCESS == ksp.GetCertificate(bCert)) {
                    return true;
                }
            }
        }
    }
    catch (...) {
        bCert.Clear();
        return false;
    }

    return false;
}

bool
KSPSign(
    WCHAR* pwcKeyName,
    Buffer& bInOut,
    Buffer& myCert)
{
    SECURITY_STATUS ss = NTE_FAIL;
    Buffer bCert;
    Buffer bHash;
    Buffer bSig;

    try {
        if (pwcKeyName) {
            KSPkey ksp((WCHAR*)L"Microsoft Smart Card Key Storage Provider");
            ss = ksp.OpenKey(pwcKeyName, AT_SIGNATURE);
            if (ERROR_SUCCESS == ss) {
                ss = ksp.GetCertificate(bCert);
            }

            if (ERROR_SUCCESS == ss) {
                myCert = bCert;
                bCert.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
                Sha256((uint8_t*)bInOut, bInOut.Size(), bHash);

                ss = ksp.SignHash((uint8_t*)bHash, bHash.Size(), bSig);
            }

            if (ERROR_SUCCESS == ss) {
                bSig.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
                bCert.Append(bSig);
                bCert.ASN1Wrap(CONSTRUCTED_SEQUENCE);
                bInOut.Clear();
                bInOut = bCert;
                return true;
            }
        }
    }
    catch (...) {
        bInOut.Clear();
        myCert.Clear();
        return false;
    }

    return false;
}

bool
VerifyTSsig(
    Buffer bData,
    Buffer bTSSig
)
{
#ifdef AUTH_SERVICE
    NdacServerConfig& conf = NdacServerConfig::GetInstance();
#else
    NdacClientConfig& conf = NdacClientConfig::GetInstance();
#endif
    try {
        SequenceReaderX seq;
        DilithiumKeyPair dpk;
        Buffer bPKfile = conf.GetValue(DILITHIUM_PUBLIC_FILE);
        if (dpk.ReadPublic((char*)bPKfile)) {
            if (seq.Initilaize(bTSSig)) {
                Buffer bNow;
                if (seq.getElementAt(0, bNow)) {
                    Buffer bSig;
                    if (seq.getValueAt(1, bSig)) {
                        Buffer bTemp = bData;
                        bTemp.Append(bNow);
                        return dpk.Verify(bTemp, bSig);
                    }
                }
            }
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

uint32_t
KSPwrapClientCertAndSigForDoc(
    WCHAR* pwcKeyName,
    uint8_t* pcHash,
    uint32_t szHash,
    uint32_t encSize,
    Buffer& bCertAndSig)
{
    SECURITY_STATUS ss = NTE_FAIL;
    Buffer bHash;
    Buffer bSig;
#ifdef AUTH_SERVICE
    return 0;
#else
    ClusterClientManager& ccm = ClusterClientManager::GetInstance();
        
    try {
        Buffer bTSsig;
        bCertAndSig.Clear();

        if (!pwcKeyName) {
            return 0;
        }

        KSPkey ksp((WCHAR*)L"Microsoft Smart Card Key Storage Provider");
        ss = ksp.OpenKey(pwcKeyName, AT_SIGNATURE);
        if (ERROR_SUCCESS == ss) {
            ss = ksp.GetCertificate(bCertAndSig);
        }

        if (ERROR_SUCCESS == ss) {
            bCertAndSig.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            Sha256(pcHash, szHash, bHash);
            ss = ksp.SignHash((uint8_t*)bHash, bHash.Size(), bSig);
        }

        if (ERROR_SUCCESS == ss) {
            if (ccm.GetTimeStampSig(bSig, bTSsig)) {//service signs the client signature plus a timestamp with the Dilithium private key
                if (VerifyTSsig(bSig, bTSsig)) {
                    bSig.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
                    bCertAndSig.Append(bSig);
                    bCertAndSig.Append(bTSsig);
                    bCertAndSig.ASN1Wrap(CONSTRUCTED_SEQUENCE);
                    return bCertAndSig.Size();
                }
            }
        }
        //if we got here, things failed
        bCertAndSig.Clear();
        return 0;
    }
    catch (...) {
        bCertAndSig.Clear();
        return 0;
    }

    return 0;
#endif
}

bool
GetGatewayIP(
    Buffer& bIP)
{
    bool bRc = FALSE;
#ifndef AUTH_SERVICE
    ULONG sz = 0;
    PIP_ADAPTER_INFO adp = NULL;
    if (GetAdaptersInfo(NULL, &sz) == ERROR_BUFFER_OVERFLOW) {
        Buffer b(sz);
        if (GetAdaptersInfo((PIP_ADAPTER_INFO)(void*)b, &sz) == NO_ERROR) {
            adp = (PIP_ADAPTER_INFO)(void*)b;
            if (adp) {
                bIP.Clear();
                bIP.Append((void*)adp->GatewayList.IpAddress.String, strlen((char*)adp->GatewayList.IpAddress.String));
                bIP.NullTerminate();
                return TRUE;// adp = adp->Next;
            }
        }
    }
#endif
    return bRc;
}

static std::atomic<double> secs = secondsSinceNewyear();
int
RandomBytes(
    Buffer& bRand)
{
    secs = secs + secondsSinceNewyear();
    bRand.Clear();
    Sha384((uint8_t*)&secs, sizeof(double), bRand);

    return bRand.Size();
}

//Thanks MS-Copilot for this method
bool
IsDomainJoined() {
    bool bRc = false;
    LPWSTR lpNameBuffer = NULL;
    NETSETUP_JOIN_STATUS status;

    if (NetGetJoinInformation(NULL, &lpNameBuffer, &status) == NERR_Success) {
        if (status == NetSetupDomainName) {
            bRc = true;
        }
        NetApiBufferFree(lpNameBuffer);
    }

    return bRc;
}

//Thanks MS-Copilot for this method
bool
IsUserLocalAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}
//Thanks MS-Copilot for this method
bool
IsUserDomainAdmin() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    PTOKEN_GROUPS groups = (PTOKEN_GROUPS)malloc(size);
    if (!groups) {
        CloseHandle(token);
        return false;
    }

    if (!GetTokenInformation(token, TokenGroups, groups, size, &size)) {
        CloseHandle(token);
        free(groups);
        return false;
    }

    bool isDomainAdmin = false;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        WCHAR* sidString = nullptr;
        if (ConvertSidToStringSidW(groups->Groups[i].Sid, &sidString)) {
            std::wstring sidW(sidString);
            // Domain Admins SID ends in -512
            if (sidW.find(L"-512") != std::wstring::npos) {
                isDomainAdmin = true;
            }
            LocalFree(sidString);
        }
    }

    CloseHandle(token);
    free(groups);
    return isDomainAdmin;
}

int
GetDomainName(Buffer& bName) {
    char buffer[256];
    DWORD size = sizeof(buffer);

    if (GetComputerNameExA(ComputerNameDnsDomain, buffer, &size)) {
        bName.Append(buffer, size);
    }

    return 0;
}

bool
LoadSecrets(
    KSPkey& ksp,
    Buffer& bSecrets) {
#ifdef AUTH_SERVICE
    MyKeyManager& mykey = MyKeyManager::GetInstance();
    NdacServerConfig& scfg = NdacServerConfig::GetInstance();
    SECURITY_STATUS ss = NTE_FAIL;
    DilithiumKeyPair& dpk = TLSContext::GetDilithium();
    Buffer bSKfile = scfg.GetValue(DILITHIUM_SECRET_FILE);
    Buffer bPKfile = scfg.GetValue(DILITHIUM_PUBLIC_FILE);

    bSecrets.Clear();
    try {
        if (mykey.LoadKeys()) {
            Buffer bEncTlsPwd;
            Buffer bPlainTlsPwd;
            Buffer bPlainSnmpPrivPwd;
            Buffer bPlainSnmpAuthPwd;
            Buffer bWrappedKeys;
            Buffer encrypted;
            Buffer bHash;
            Buffer hex;
            Buffer bFile = scfg.GetValue(TLS_PRIV_KEY_PWD_FILE);

            if (!mykey.WrapDerivedKeys(bWrappedKeys)) {
                return false;
            }

            readFile((char*)bFile, bEncTlsPwd);
            if (bEncTlsPwd.Size() == 0) {
                return false;
            }

            if (ERROR_SUCCESS != ksp.Decrypt((uint8_t*)bEncTlsPwd, bEncTlsPwd.Size(), bPlainTlsPwd)) {
                return false;
            }

            if (bPlainTlsPwd.Size() == 0) {
                return false;
            }
            bPlainTlsPwd.NullTerminate();

            Sha384((uint8_t*)bPlainTlsPwd, bPlainTlsPwd.Size(), bHash);
            if (bHash.Size() != SHA384_DIGEST_LENGTH) {
                return false;
            }

            hex = scfg.GetValue(SNMP_PRIV_PASSWORD);
            hexDecode((uint8_t*)hex, hex.Size(), encrypted);
            AES_CBC_Decrypt((uint8_t*)bHash, (uint8_t*)bHash + 32, (uint8_t*)encrypted, encrypted.Size(), bPlainSnmpPrivPwd);
            bPlainSnmpPrivPwd.NullTerminate();

            hex = scfg.GetValue(SNMP_AUTH_PASSWORD);
            hexDecode((uint8_t*)hex, hex.Size(), encrypted);
            AES_CBC_Decrypt((uint8_t*)bHash, (uint8_t*)bHash + 32, (uint8_t*)encrypted, encrypted.Size(), bPlainSnmpAuthPwd);
            bPlainSnmpAuthPwd.NullTerminate();

            SnmpTrap::SetPwds(bPlainSnmpPrivPwd, bPlainSnmpAuthPwd);

            //open Dilithium
            if (!dpk.Open((char*)bSKfile, (char*)bPKfile, (char*)bPlainTlsPwd)) {
                char cMsg[] = "Local Service TLS failed to start due to missing Dilithium key pair.";
                SnmpTrap trap(cMsg, (uint32_t)strlen(cMsg));
                return false;
            }

            //wrap the secrets
            bPlainTlsPwd.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bSecrets.Append(bPlainTlsPwd);
            bPlainSnmpPrivPwd.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bSecrets.Append(bPlainSnmpPrivPwd);
            bPlainSnmpAuthPwd.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
            bSecrets.Append(bPlainSnmpAuthPwd);
            bSecrets.Append(bWrappedKeys);
            bSecrets.ASN1Wrap(CONSTRUCTED_SEQUENCE);

            return true;
        }
    }
    catch (...) {
        bSecrets.Clear();
        return false;
    }
#endif
    return false;
}

#ifdef AUTH_SERVICE
WCHAR*
ChooseUserKey()
{
    return (WCHAR*)MY_SMARTCARD_CONTAINER;
}
#else
extern WCHAR* ClientChooseUserKey();
WCHAR*
ChooseUserKey()
{
    return ClientChooseUserKey();
}
#endif

// Returns true if path exists and is a directory.
bool
DirectoryExistsA(
    const char* pcPath)
{
    if (pcPath) {
        DWORD attrs = GetFileAttributesA(pcPath);
        return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    }
    return false;
}

bool
DirectoryExistsW(
    const wchar_t* pwcPath)
{
    if (pwcPath) {
        DWORD attrs = GetFileAttributesW(pwcPath);
        return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    }
    return false;
}

//MS-Copilot provided
//This method locks the directory specified in the input
HANDLE
LockPath(
    const wchar_t* pwcPath
)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    Buffer bFilePath;
    // Lock the entire file: offset = 0, length = MAXDWORD:MAXDWORD
    LARGE_INTEGER length;
    length.QuadPart = 0xFFFFFFFFFFFFFFFFULL; // lock "infinite" length

    if (!pwcPath) {
        return INVALID_HANDLE_VALUE;
    }

    try {
        bFilePath.Append((void*)pwcPath, wcslen(pwcPath) * sizeof(wchar_t));
        bFilePath.Append((void*)L"\\LockFile.lck", wcslen(L"\\LockFile.lck") * sizeof(wchar_t));
        bFilePath.NullTerminate_w();

        hFile = CreateFileW(
            (wchar_t*)bFilePath,
            GENERIC_READ | GENERIC_WRITE,      // required for LockFile
            0,                                 // no sharing ? exclusive access
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return INVALID_HANDLE_VALUE;
        }

        if (!LockFile(hFile, 0, 0, length.LowPart, length.HighPart)) {
            CloseHandle(hFile);
            return INVALID_HANDLE_VALUE;
        }
    }
    catch (...) {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
        return INVALID_HANDLE_VALUE;
    }
        
    return hFile;
}

//This method locks the directory where the specified file or directory lives
HANDLE
LockFilePath(
    const wchar_t* pwcFile
)
{
    HRESULT hr;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    Buffer bFilePath;
    // Lock the entire file: offset = 0, length = MAXDWORD:MAXDWORD
    LARGE_INTEGER length;
    length.QuadPart = 0xFFFFFFFFFFFFFFFFULL; // lock "infinite" length

    if (!pwcFile) {
        return INVALID_HANDLE_VALUE;
    }

    try {
        wchar_t wcTemp[MAX_PATH];
        wcscpy_s(wcTemp, pwcFile);

        hr = PathCchRemoveFileSpec(wcTemp, MAX_PATH);
        if ((hr != S_OK) && (hr != S_FALSE)) {
            return INVALID_HANDLE_VALUE;
        }

        if (FAILED(StringCchCatW(wcTemp, MAX_PATH, L"\\LockFile.lck"))) {
            return INVALID_HANDLE_VALUE;
        }

        hFile = CreateFileW(
            (wchar_t*)wcTemp,
            GENERIC_READ | GENERIC_WRITE,      // required for LockFile
            0,                                 // no sharing ? exclusive access
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return INVALID_HANDLE_VALUE;
        }

        if (!LockFile(hFile, 0, 0, length.LowPart, length.HighPart)) {
            CloseHandle(hFile);
            return INVALID_HANDLE_VALUE;
        }
    }
    catch (...) {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
        return INVALID_HANDLE_VALUE;
    }

    return hFile;
}

void
UnlockEntireFile(
    HANDLE hFile)
{
    LARGE_INTEGER length;
    length.QuadPart = 0xFFFFFFFFFFFFFFFFULL;

    if (hFile != INVALID_HANDLE_VALUE) {
        UnlockFile(hFile, 0, 0, length.LowPart, length.HighPart);
        CloseHandle(hFile);
    }
}
