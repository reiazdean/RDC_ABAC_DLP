#pragma once
#include <mutex>
#include <condition_variable>
#include <string>
#include <vector>
#include <thread>
#include "Utils.h"

using std::vector;
using std::pair;
using std::string;
using std::thread;
using std::mutex;
using std::condition_variable;

namespace ReiazDean {
    class MyKeyManager {
        //************   Cons/Destruction   ***************
    private:
    protected:
        MyKeyManager();
        virtual ~MyKeyManager();
    public:
        MyKeyManager(const MyKeyManager&) = delete;
        MyKeyManager(MyKeyManager&&) = delete;
        //************   Class Attributes   ****************
    private:
        static MyKeyManager TheMyKeyManager;
    protected:
    public:
        static MyKeyManager& GetInstance() {
            return TheMyKeyManager;
        };
        
        static uint32_t CountKeys();
        static uint32_t ExportKeys(Buffer& bOut, uint8_t* pcPwd, uint32_t pwdSz);
        //************   Class Methods   *******************
    private:
    protected:

    public:
        //************ Instance Attributes  ****************
    private:
        vector<std::pair<Buffer, Buffer>> myDerivedSymmetricKeys;
        uint32_t                       myKeyIndex;
        mutex                          myMutex;

    public:

        //************ Instance Methods  *******************
    private:
    protected:
        bool                           TestKeyBlockSize(Buffer& k);
        bool                           TestKeyNonBlockSize(Buffer& k);
        bool                           TestKey(Buffer& k);
        bool                           DeriveRootKey(WCHAR* pwcKeyName, Buffer& bDerived);
        bool                           GetDerivedKey(WCHAR* pwcKeyName, Buffer& bDerived);

    public:
        MyKeyManager&                  operator=(const MyKeyManager& original) = delete;
        MyKeyManager&                  operator=(MyKeyManager&& original) = delete;
        bool                           WrapDerivedKeys(Buffer& bWrapped);
        bool                           UnwrapDerivedKeys(Buffer bWrapped);
        bool                           LoadKeys();
        bool                           CalculateEncryptionKey(Mandatory_AC& mac, Buffer& bCalculatedKey, Buffer& bKeyName);
        bool                           CalculateDecryptionKey(WCHAR* pwcHSMkey, Mandatory_AC& mac, Buffer& bCalculatedKey);
    };
}

