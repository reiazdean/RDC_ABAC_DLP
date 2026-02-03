#pragma once
#include <iostream>
#include <string>
#include <stdlib.h>
#include <assert.h>
#include <vector>
#include "Utils.h"

using std::vector;
using std::string;

#ifdef AUTH_SERVICE
#define     CONF_DIR                   "\\ReiazDeanIncServer"
#else
#define     CONF_DIR                   "\\ReiazDeanIncClient"
#endif
#define     CLIENT_CONF_FILE           "\\ReiazDeanClient.conf"
#define     SERVER_CONF_FILE           "\\ReiazDeanServer.conf"

//Server elements
#define             LOCAL_UNIX_SOCKET_NAME       "Local Unix Socket Name"
#define             TLS_PORT_STRING              "TLS Port"
#define             TLS_PRIV_KEY_FILE            "TLS Private Key File"
#define             TLS_PRIV_KEY_PWD_FILE        "TLS Private Key Password File"
#define             TLS_CERTIFICATE_FILE         "TLS Server Certificate File"
#define             TLS_CERT_FILE_REQ            "TLS PKCS10 File"
#define             TRUSTED_CA_FILE              "Trusted CA Certificate File"
#define             CRL_FILE                     "Certificate Revocation File"
#define             SERVER_USE_DNS_RESOLVE       "Use DNS Resolution"
#define             DOCUMENT_ROOT_FILE_LOCATION  "Document Root Location"
#define             HOST_NODE_SECRET_FILE        "Client Node Secrets File"
#define             REVOKED_CERT_SN_FILE         "Revoked Cert Serial Number File"
#define             KEY_STORAGE_PROVIDER         "Key Storage Provider Name"
#define             KSP_NEEDS_PASSWORD           "Does The KSP Require A User Supplied Password?(yes|no)"
#define             DILITHIUM_SECRET_FILE        "Dilithium Secret File Name"
#define             DILITHIUM_PUBLIC_FILE        "Dilithium Public File Name"
#define             CLUSTER_MEMBERS_FILE         "Cluster Member Names"
#define             SNMP_HOST_STRING             "SNMP Host"
#define             SNMP_PORT_STRING             "SNMP Port"
#define             SNMP_PRIV_PASSWORD           "SNMP Privacy Password"
#define             SNMP_AUTH_PASSWORD           "SNMP Authentication Password"
//Client Elements
#define             AUTH_HOST_STRING           "Authorization Hosts"
#define             CLIENT_NODE_SECRET         "Node Secret"
#define             CLIENT_USING_HSM           "Using HSM"
#define             NON_PARALLEL_APPS          "Non Parallel Apps"
#define             NON_PARALLEL_APPS_POLICY   "Non Parallel Apps Policy"
#define             APP_ICONS_ROOT_DIR         "Application Icons Root Directory"
#define             NON_SANDBOX_ICONS          "Non Sandbox Application Icons"
#define             SANDBOX_ICONS              "Sandbox Application Icons"
#define             SANDBOX_INSTALLER          "Sandbox Installation String"


#ifdef OS_WIN32
constexpr auto EOLN = L"\r\n";
#else
constexpr auto EOLN = "\n";
#endif

namespace ReiazDean {
    class NdacConfig {
        //************   Cons/Destruction   ***************
    protected:
        NdacConfig();
    public:
        NdacConfig(const NdacConfig&) = delete;
        NdacConfig(NdacConfig&&) = delete;
        virtual ~NdacConfig();

        //************   Class Attributes   ****************
    private:
    public:

        //************   Class Methods   *******************
    private:
    protected:
    public:

        //************ Instance Attributes  ****************
    protected:
        /*
        * myConfigItems = {string key,
        *                  string value
        *                  bool encrypted,
        *                  bool pathRequired,
        *                  bool hexEncoded,
        *                  bool userModifiable,
        *                 }
        */
        vector<ConfigItems>  myConfigItems;
        string myFilePath;
        string mySeps;
        bool isValid;

    public:

        //************ Instance Methods  *******************
    private:
        void                          determinePath();
    protected:
        void                          DoReadConfigFile(const char* filename);
        uint8_t                       DoSave(const char* filename);
    public:
        NdacConfig&                   operator=(const NdacConfig& original) = delete;
        NdacConfig&                   operator=(NdacConfig&& original) = delete;
        virtual string                GetValue(const string& key);
        virtual void                  GetValue(const char* pcVal, Buffer& val);
        virtual Buffer                GetValue(const char* pcVal);
        virtual Buffer                GetValueW(const char* pcVal);
        virtual void                  SetValue(const string& key, const string& value);
        virtual void                  ReadConfigFile() = 0;
        virtual uint8_t               Save() = 0;
        virtual string&               GetMyFilePath() { return myFilePath; };
        virtual void                  Finalize();
        virtual bool                  IsValid() { return isValid; };
    };

    class NdacServerConfig : public NdacConfig {
    private:
        static NdacServerConfig TheNdacServerConfig;
    private:
        NdacServerConfig();
        virtual ~NdacServerConfig();
    public:
        NdacServerConfig(const NdacServerConfig&) = delete;
        NdacServerConfig(NdacServerConfig&&) = delete;
        static NdacServerConfig& GetInstance() {
            return TheNdacServerConfig;
        };
    protected:
        bool                          CertMatchesPK(Buffer& bCert);
        bool                          DownloadCAcert(Buffer& bCert);
        bool                          CertVerifiesWithBundle(Buffer& bCert);
        bool                          ChooseKSP(Buffer& bKSP);
        bool                          OpenKSP();
        bool                          OpenOrCreateKSPkey();
        bool                          KSPencrypt(Buffer& bSecret, Buffer& bEncSecret);
        bool                          GenerateOrOpenDilithium();
        bool                          InitiateServerCSR(char* csrFileName);
        bool                          Prerequisites();
        bool                          FileChecks();
    public:
        NdacServerConfig&             operator=(const NdacServerConfig& original) = delete;
        NdacServerConfig&             operator=(NdacServerConfig&& original) = delete;
        virtual bool                  Configure();
        virtual void                  ReadConfigFile();
        virtual uint8_t               Save();
        virtual bool                  GenerateServerCSR();
        virtual bool                  DeployServerCertificate(char* pcCert);
        virtual bool                  DeployCACertificate(char* pcCert);
    };

    class NdacClientConfig : public NdacConfig {
    public:
        enum SandboxedState { NONE, INSIDE, OUTSIDE, UNKNOWN };
    private:
        static NdacClientConfig TheNdacClientConfig;
    private:
        NdacClientConfig();
        virtual ~NdacClientConfig();
    public:
        NdacClientConfig(const NdacClientConfig&) = delete;
        NdacClientConfig(NdacClientConfig&&) = delete;
        static NdacClientConfig& GetInstance() {
            return TheNdacClientConfig;
        };

    protected:
    public:
        NdacClientConfig&             operator=(const NdacClientConfig& original) = delete;
        NdacClientConfig&             operator=(NdacClientConfig&& original) = delete;
        virtual void                  ReadConfigFile();
        virtual uint8_t               Save();
        vector<ConfigItems>&          GetConfigItems() { return myConfigItems; };
    };
}
