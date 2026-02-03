#pragma once
#include <Windows.h>
#include <commctrl.h>
#include <mutex>
#include <string>
#include <vector>
#include <time.h>
#include "SequenceReader.h"

using std::mutex;
using std::vector;

namespace ReiazDean {
    class SnmpTrap {
        //************   Cons/Destruction   ***************
    private:
    public:
        SnmpTrap();
        SnmpTrap(char* pcTrap, uint32_t szTrap);
        SnmpTrap(const SnmpTrap&) = delete;
        SnmpTrap(SnmpTrap&&) = delete;
        virtual ~SnmpTrap();

        //************   Class Attributes   ****************
    private:
        static std::mutex s_Mutex;
        static Buffer s_PrivPwd;
        static Buffer s_AuthPwd;
    public:
        //************   Class Methods   *******************
    private:
    protected:
    public:
        static void SetPwds(Buffer& privPwd, Buffer& authPwd);
        static Buffer GetPrivPwd();
        static Buffer GetAuthPwd();
        //************ Instance Attributes  ****************
    private:
        Buffer m_PreDigestedTrap;
        Buffer m_DigestedTrap;
        static std::atomic<uint32_t> s_MsgID;   
        Buffer m_msgAuthoritativeEngineID;
        uint32_t m_Boots;
        Buffer m_msgAuthoritativeEngineBoots;
        uint32_t m_Times;
        Buffer m_msgAuthoritativeEngineTime;
        Buffer m_msgPrivacyParameters;
        Buffer m_msgUserName;
        Buffer m_msgAuthenticationParameters;
        Buffer m_msgGlobalData;
        Buffer m_msgSecurityParameters;
        Buffer m_contextEngineID;
        Buffer m_contextName;
        Buffer m_EncryptedPDU;
        uint8_t m_AESkey[16];
        uint8_t m_IV[16];
        uint8_t m_PrivParam[8];//the random salt value
        uint8_t m_AuthParam[12];//the random salt value
        uint8_t m_HMACkey[20];
    public:
        //************ Instance Methods  *******************
    private:
        int Send();
        void CalculateAESKey(char* pcPassword);
        void CalculateIV();
        void CalculateHMACKey(char* pcPassword);
        void BuildVarBinds(char* pcMessage, Buffer& bVBs);
        void ProcessPDU(char* pcMessage, Buffer& bScopedPDU);
        int8_t AES_CFB_Encrypt(const uint8_t* plaintext, uint32_t len, Buffer& bOut);
        int8_t AES_CFB_Decrypt(const uint8_t* ciphertext, uint32_t len, Buffer& bOut);
        int8_t DigestMessage();
        bool ReassembleTrap();
    public:
        SnmpTrap& operator=(const SnmpTrap& original) = delete;
        SnmpTrap& operator=(SnmpTrap&& original) = delete;
#ifdef _DEBUG
        void KnownKeyTests();
        void DecryptionTest();
#endif
    };
}



