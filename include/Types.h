#pragma once
#ifdef AUTH_SERVICE
#include <Windows.h>
#endif
#include <sys/types.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/aes.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <string>
#include <thread>

using std::thread;
using std::string;
using std::unique_ptr;
using std::shared_ptr;

#ifdef OS_WIN32
#define     MY_CLIENT_CERT       L".tls\\clientCert.crt"
#define     MY_CLIENT_PRIV_KEY   L".tls\\clientKey.key"
#define     MY_SMARTCARD_CONTAINER   L"RDCIncKeyContainer"
#define     MY_SERVER_KSP_KEY_NAME   L"RDCIncServiceEncKey"
#define     SVCDESC "RDC Inc. Authorization Service for determining a domain user's security level and category and providing the calculated cipher keys!"
#define     SVCNAME    "RDCInc_Auth_Service"
#else
//#define             MY_CA_CERT           "/usr/share/pki/ca-trust-source/anchors/CAFile.crt"
#define             MY_CLIENT_CERT       ".tls/clientCert.crt"
#define             MY_CLIENT_PRIV_KEY   ".tls/clientKey.key"
#endif

#define LDAP_SEPS "$===$"

#define MY_MAX_PATH           (MAX_PATH - 80)
#define MAX_LINE              1024
#define MAX_PASSWD            128
#define MAX_NAME              512
#define MAX_ARGS              32
#define MAX_ARG               128
#define MAX_MLS_LEVEL         8
#define MAX_MCS_LEVEL         MAX_MLS_LEVEL
#define MAX_DESCRIPTION_SZ    48
#define AES_256_KEY_SZ        32
#define AES_256_IV_SZ         16
#define AES_SZ                (AES_256_KEY_SZ + AES_256_IV_SZ)
#define FILE_ENCRYPTION_SZ    2048
#define FILE_DECRYPTION_SZ    (FILE_ENCRYPTION_SZ + AES_BLOCK_SIZE)
#define FILE_TRANSFER_CHUNK_SZ 4096

//openssl\crypto\objects\obj_def.h
const uint8_t NullOID[2] = { 0x05, 0x00 };
const uint8_t SHA256AlgOID[15] = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 };
const uint8_t SHA384AlgOID[15] = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00 };
const uint8_t SHA512AlgOID[15] = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00 };
const uint8_t RSASigSHA256AlgOID[15] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };//a sequence of an OID(06) and NULL(05)
const uint8_t RSASigSHA384AlgOID[15] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00 };//a sequence of an OID(06) and NULL(05)
const uint8_t RSASigSHA512AlgOID[15] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00 };//a sequence of an OID(06) and NULL(05)

namespace ReiazDean {
    enum ServiceType {
        SVC_TYPE_AUTH_SERVICE,
        SVC_TYPE_PROXY_SERVICE,
        SVC_TYPE_NONE = 0xFFFFFFFF
    };

    enum Commands {
        CMD_GET_SERVER_NONCE,
        CMD_GET_CLIENT_SANDBOX_STATE,
        CMD_GET_CLIENT_SANDBOX_SCRIPT,
        CMD_EXCHANGE_ECDH_KEYS,
        CMD_EXCHANGE_KYBER_KEYS,
        CMD_SEND_NODE_SECRET,
        CMD_SEND_TLS_PK_PASSWD,
        CMD_EXCHANGE_SECRETS,
        CMD_EXCHANGE_CLUSTER_MBRS,
        CMD_CLUSTER_ADD_MBR,
        CMD_CLUSTER_REMOVE_MBR,
        CMD_CLUSTER_REGISTER_CLIENT,
        CMD_GET_MLS_MCS_AES_ENC_KEY,
        CMD_GET_MLS_MCS_AES_DEC_KEY,
        CMD_UPLOAD_DOCUMENT,
        CMD_DOWNLOAD_DOCUMENT,
        CMD_PUBLISH_DOCUMENT,
        CMD_DECLASSIFY_DOCUMENT,
        CMD_UPLOAD_CERT_REQUEST,
        CMD_DOWNLOAD_CERTIFICATE,
        CMD_DOWNLOAD_SW_INSTALLER,
        CMD_DOWNLOAD_DECLASSIFIED,
        CMD_VERIFY_DOCUMENT,
        CMD_GET_DOCUMENT_TREE,
        CMD_GET_DOCUMENT_NAMES,
        CMD_RELOAD_REGISTERED_CLIENTS,
        CMD_RELOAD_ROOT_KEYS,
        CMD_STOP_LOCAL_SERVICE,
        CMD_OOB_AUTHENTICATE,
        CMD_OOB_GET_ICON_DIR,
        CMD_OOB_GET_SC_CERT,
        CMD_OOB_SC_SIGN,
        CMD_OOB_SC_SIGN_DOC_HASH,
        CMD_TIMESTAMP_SIGN,
        CMD_NULL
    };

    enum Responses {
        RSP_SUCCESS,
        RSP_NOT_AUTHORIZED,
        RSP_MCS_UNAUTHORIZED,
        RSP_MLS_UNAUTHORIZED,
        RSP_HOST_MLS_UNAUTHORIZED,
        RSP_NOT_VALID_NODE,
        RSP_INVALID_COMMAND,
        RSP_KEY_GEN_ERROR,
        RSP_MEMORY_ERROR,
        RSP_DIGEST_ERROR,
        RSP_CIPHER_ERROR,
        RSP_FILE_ERROR,
        RSP_SOCKET_IO_ERROR,
        RSP_INTERNAL_ERROR,
        RSP_SIGNATURE_INVALID,
        RSP_HASH_MISMATCH,
        RSP_FILE_MOVE_ERROR,
        RSP_CERT_REVOKED,
        RSP_CERT_INVALID,
        RSP_NO_ITEMS_FOUND,
        RSP_CANNOT_LOCK_FILE,
        RSP_COMMAND_TIMEOUT,
        RSP_MAX_PATH_EXCEEDED,
        RSP_NULL
    };

    typedef struct {
        std::string sKey;
        std::string sValue;
        bool bEncrypted;
        bool bPathRequired;
        bool bHexEncoded;
        bool bUserModifiable;
    } ConfigItems;

    typedef struct {
        Commands  command;
        uint32_t  szData;
    } CommandHeader;

    typedef struct {
        Responses  response;
        uint32_t    szData;
    } ResponseHeader;

    typedef struct {
        int      sock;
        SSL      *ssl;
    } IOThreadArgs;

    typedef struct {
        bool bNewDoc;
        char **argv;           /* Command to be executed by child, with args */
    } NS_child_args;

    typedef struct {
        uint16_t  mls_level;
        char      mcs[MAX_MCS_LEVEL];
        char      mls_desc[MAX_DESCRIPTION_SZ];
        char      implied_mls_desc[MAX_MLS_LEVEL][MAX_DESCRIPTION_SZ];
        char      mcs_desc[MAX_MCS_LEVEL][MAX_DESCRIPTION_SZ];
        char      mls_doc_name[MAX_NAME];
        uint32_t    mls_doc_size;
    } Mandatory_AC;

#define   ROOT_KEY_HASH_HEX_SZ          (SHA256_DIGEST_LENGTH * 2)
#define   ENC_AES_KEY_SZ                (AES_SZ + AES_BLOCK_SIZE)
#define   HEX_ENC_AES_KEY_SZ            (ENC_AES_KEY_SZ + ENC_AES_KEY_SZ)

    typedef struct {
        Mandatory_AC  docMAC;
        WCHAR         hsmKeyName[MAX_NAME];              //used to derive the cipher keys
    } AuthorizationRequest;

    typedef struct {
        Mandatory_AC  docMAC;
        WCHAR         hsmKeyName[MAX_NAME];          //used to derive the cipher keys
        char          encryptionKey[AES_SZ];                      //key bytes in plain sight. Client must zero after use
        char          decryptionKey[AES_SZ];                      //key bytes in plain sight. Client must zero after use
    } AuthorizationResponse;

    typedef struct {
#ifndef OS_WIN32
        pid_t     pid;
        pid_t     parent_pid;
#else
        int       pid;
        int       parent_pid;
#endif
        char      name[MAX_LINE];
    } ProcInfomation;

    typedef int (callback_t)(std::string, bool);
    
    typedef struct {
        callback_t* function;
        char        path[MAX_LINE];
    } NotifyInformation;

    typedef int (ui_callback_t)(HWND);

    typedef struct {
        ui_callback_t* function;
        HWND hWnd;
    } NotifyView;

    typedef struct {
        int         count;
        char        argv[MAX_ARGS][MAX_ARG];
    } CommandLineArgs;

    typedef void* (threadProcedure)(void*);

    typedef struct {
        threadProcedure* threadFct;
        void* args;
        thread* pThread;
    } ThreadArgs;

    typedef struct _DialogItem {
        DWORD			dwStyle;
        SHORT			dwId;
        SHORT			dwX;
        SHORT			dwCX;
        SHORT			dwY;
        SHORT			dwCY;
        WORD			wClassLow;
        WORD			wClassHi;
        DWORD			dwTextIndex;

    } DialogItem;
}

