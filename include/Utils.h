#pragma once
#include <WinSock2.h>
#include <ncrypt.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <netfw.h>
#include <tchar.h> 
#include <strsafe.h>
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>
#include <string.h>
#include <time.h>  
#include <sys/types.h>  
#include <sys/stat.h>   
#include <errno.h>  
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <Ws2tcpip.h>
#include <afunix.h>
#include "iphlpapi.h"
#include <Lm.h>
#include <conio.h>
#include <sddl.h>
#include <pathcch.h>
#include <math.h>
#include "Buffer.h"
#include "KSPkey.h"

using std::map;
using std::vector;
using std::string;
using std::ostringstream;
using std::unique_ptr;
using std::wstring;

using namespace ReiazDean;

#define             MAX_WANT_TRIES    20
#define             MAX_READ_SIZE     1024*4
#define             MAX_WRITE_SIZE    MAX_READ_SIZE
#define             CERT_FILE_TYPE_DER 0
#define             CERT_FILE_TYPE_PEM 1
#define             CERT_FILE_TYPE_UNK 9999

#ifndef minimum
#define minimum(x, y) x < y ? x : y
#endif

LPWORD
lpwAlign(
    LPWORD lpIn,
    ULONG dw2Power = 4
);

FILE*
f_open_f(
    char* pcName,
    char* pcMode
);

FILE*
f_open_u(
    wchar_t* pcName,
    wchar_t* pcMode
);

uint32_t
ReadEncodedLength(
    FILE* fp);

uint32_t
ReadMemoryEncodedLength(
    uint8_t* mem,
    uint32_t& pos);

bool
PEM_Decode(
    Buffer& pem,
    Buffer& der,
    uint32_t& iSize);

void
openssl_error(
    char* pcApi);

void
init_openssl_library(void);

char
getChar();

int
my_cb(
    char *buf,
    int size,
    int rwflag,
    void *u);

void
readPassword(
    char* pwdBuf,
    uint32_t szBuf);

bool
readConsole(
    char* pcPrompt,
    char* pcOutBuf,
    uint32_t* pdwLen);

bool
doTlsServerPasswordEx(
    Buffer& bPwd);

bool
doTlsServerPasswordSilently(
    Buffer& bPwd,
    char* pcPIN);

bool
doTlsClientPasswordText(
    const char* pcPwd);

bool
GetHostAddrInfo(
    Buffer& bIn,
    Buffer& bOut);

SOCKET
OpenUnixSocket(
    bool bServer);

void
CloseUnixSocket(
    SOCKET sock);

SOCKET
OpenClientInetSocket(
    char* pcHost,
    int port);

SOCKET
OpenServerInetSocket(
    int port);

int
SockRead(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess);

int
BlockingSockRead(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess);

int
SockWrite(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess);

int
BlockingSockWrite(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess);

int
SockReadAppend(
    SOCKET fd,
    Buffer &b);

int
Select(
    SOCKET fd,
    int secs,
    int usecs,
    bool b_read
);

int
NonBlockingRead(
    SOCKET fd,
    Buffer &b,
    int timeout = 0);

int
BlockingRead(
    SOCKET fd,
    Buffer& b);

int
NonBlockingWriteEx(
    SOCKET fd,
    char* pcMessIn,
    uint32_t szMess,
    int timeout = 0);

int
NonBlockingWrite(
    SOCKET fd,
    Buffer &b,
    int timeout = 0);

void
SetToBlock(SOCKET sock);

void
SetToNotBlock(SOCKET sock);

void
CloseSocket(SOCKET sock);

double
secondsSinceNewyear();

bool
hexEncode(
    uint8_t* pcRaw,
    uint32_t szRaw,
    Buffer &b);

bool
hexDecode(
    uint8_t* pcHex,
    uint32_t szHex,
    Buffer &b);

uint8_t
saveToFile(
    int8_t* fname,
    int8_t* pcData,
    uint32_t szData);

int32_t
readFile(
    char* fname,
    Buffer& data);

int32_t
readFile_w(
    wchar_t* fname,
    Buffer& data);

void
ReverseMemory(
    uint8_t *pbData,
    uint32_t szData);

void
stringWrite(
    int8_t*  pcBuffer,
    uint32_t    lenBuffer,
    const int8_t *format,
    ...
);

void
stringCat(
    int8_t*   pcOne,
    uint32_t   lenOne,
    int8_t*   pcTwo
);

int8_t* strToken(
    int8_t*         pcBuf,
    const int8_t*   pcSeps,
    int8_t**        ppcLast
);

uint32_t splitStringW(
    wchar_t* pwcString,
    wchar_t* pwcSeps,
    std::vector<wchar_t*>& pieces
);

uint32_t splitStringA(
    char* pcString,
    char* pcSeps,
    std::vector<char*>& pieces
);

uint32_t ipToChars(
    int8_t*     pcIP
);

void asDottedIp(
    uint32_t ip,
    Buffer& bIP
);

uint32_t incrementIp(
    uint32_t ip
);

uint32_t decrementIp(
    uint32_t ip
);

void IncrementIp(
    const Buffer& bIPin,
    Buffer& bIPout
);

void DecrementIp(
    const Buffer& bIPin,
    Buffer& bIPout
);

uint32_t
Sha256(
    uint8_t* in,
    uint32_t  len,
    Buffer&  out
);

uint32_t
Sha384(
    uint8_t* in,
    uint32_t  len,
    Buffer&  out
);

uint32_t
Sha512(
    uint8_t* in,
    uint32_t  len,
    Buffer&  out
);

uint32_t
AES_CBC_Encrypt(
    const uint8_t* pucKey,
    const uint8_t* pucIV,
    const uint8_t* plaintext,
    uint32_t         len,
    Buffer&        bEnc
);

uint32_t
AES_CBC_Decrypt(
    const uint8_t* pucKey,
    const uint8_t* pucIV,
    const uint8_t* ciphertext,
    uint32_t         len,
    Buffer&        bPlain
);

uint32_t
RSA_Encrypt(
    wchar_t* pcCertFile,
    uint8_t* plain,
    uint32_t szPlain,
    Buffer& bEnc
);
   
uint32_t
RSA_Decrypt(
    wchar_t* pcPrivKeyFile,
    uint8_t* enc,
    uint32_t szEnc,
    uint8_t* pcPwd,
    Buffer& bPlain
);

uint32_t
RSA_PubKey_Encrypt(
    EVP_PKEY* pubkey,
    uint8_t* plain,
    uint32_t szPlain,
    Buffer& bEnc
);

uint32_t
RSA_Sign(
    wchar_t* pcPrivKeyFile,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* pcPasswd,
    Buffer& bSignature
);

int
VerifySignatureCNG(
    Buffer bCert,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature
);

bool
RSA_Verify(
    wchar_t* pcCertFile,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature
);

bool
RSA_VerifyBIO(
    uint8_t* pcCertData,
    uint32_t szCertData,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature
);

bool
RSA_VerifyDER(
    uint8_t* pcCertData,
    uint32_t szCertData,
    uint8_t* hash,
    uint32_t szHash,
    uint8_t* signature,
    uint32_t szSignature
);

bool
VerifyCertWithBundle(
    char* pcBundleFile,
    const uint8_t* pcCertData,
    uint32_t szCertData
);

bool
VerifyCertRequestFile(
    const char* pcRequestFile
);

bool
VerifyPEMCertWithBundle(
    const char* pcBundleFile,
    const char* pcCertData,
    uint32_t szCertData
);

uint32_t
RSA_PubKey_Decrypt(
    uint8_t* enc,
    uint32_t szEnc,
    Buffer& bPlain,
    uint8_t* pcCertFile
);

bool
PEMcert_to_DERcert(
    Buffer& cert,
    uint32_t& sz
);

int
CertFileType(
    char* pcCertFile
);

wstring
printAR(
    AuthorizationResponse* pAR
);

void
LogBinary(
    FILE* fp,
    uint8_t* label,
    uint8_t* data,
    uint32_t len);

int
GetDirectoryContents(
    wchar_t* dirName,
    Buffer& b);

int
GetDirectoryContentsWithExtension(
    wchar_t* dirName,
    wchar_t* ext,
    Buffer& b);

int
GetSubDirectories(
    wchar_t* dirName,
    Buffer& b);

int
GetDirectoryTree(
    wchar_t* dirName,
    Buffer& b,
    int level);

int
GetFilteredDirectoryTree(
    wchar_t* dirName,
    Buffer& b,
    Mandatory_AC& userMac,
    int level);

char*
GetUtf8FromWchar(
    const wchar_t* pwcTemp,
    Buffer& b);

wchar_t*
GetWcharFromUtf8(
    const char* pcUtf8,
    Buffer& b);

time_t
AsTime_t(
    Buffer& obj);

bool
KSPSign(
    WCHAR* pwcKeyName,
    Buffer& bInOut,
    Buffer& myCert);

bool
KSPGetUserCertificate(
    WCHAR* pwcKeyName,
    Buffer& bCert);

uint32_t
KSPwrapClientCertAndSigForDoc(
    WCHAR* pwcKeyName,
    uint8_t* pcHash,
    uint32_t szHash,
    uint32_t encSize,
    Buffer& bCertAndSig);

bool
GetGatewayIP(
    Buffer& bIP);

int
RandomBytes(
    Buffer& bRand);

bool
IsDomainJoined();

bool
IsUserDomainAdmin();

bool
IsUserLocalAdmin();

int
GetDomainName(Buffer& bName);

bool
LoadSecrets(
    KSPkey& ksp,
    Buffer& bSecrets);

WCHAR*
ChooseUserKey();

bool
DirectoryExistsA(
    const char* pwcPath
);

bool
DirectoryExistsW(
    const wchar_t* pwcPath
);

HANDLE
LockFilePath(
    const wchar_t* pwcFile
);

HANDLE
LockPath(
    const wchar_t* pwcFile
);

void
UnlockEntireFile(
    HANDLE hFile
);

