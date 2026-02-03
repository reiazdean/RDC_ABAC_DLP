#pragma once
#include <stdint.h>
#include <string>
#include <mutex>
#include "Utils.h"
#include "LatticeKeyPair.h"

using std::mutex;

//*************************************************
//
//CLASS    DilithiumKeyPair    
//
//*************************************************
namespace ReiazDean {
    class DilithiumKeyPair : public LatticeKeyPair {
        //************Cons/Destruction***********
    private:
    protected:
    public:
        DilithiumKeyPair();
        DilithiumKeyPair(const DilithiumKeyPair&) = delete;
        DilithiumKeyPair(DilithiumKeyPair&&) = delete;
        virtual ~DilithiumKeyPair();

        //************Class Attributes  ****************
    private:
    protected:
    public:

        //************Class Methods*******************
    private:
    protected:
    public:
        static bool                   Test();

        //************Instance Attributes****************
    private:
    protected:
        //************Instance Methods****************
    private:
    protected:
        bool                          PersistSecret(char* pcFile, char* pcPassword);
        bool                          PersistPublic(char* pcFile);
        bool                          OpenSecret(char* pcFile, char* pcPassword);
        bool                          OpenPublic(char* pcFile);
    public:
        DilithiumKeyPair&             operator=(const DilithiumKeyPair &original);
        DilithiumKeyPair&             operator=(DilithiumKeyPair&& original) = delete;
        virtual int32_t               Create();
        virtual uint32_t              Sign(const Buffer& bData, Buffer& bSignature);
        virtual bool                  Verify(const Buffer& bData, const Buffer bSignature);
        bool                          Persist(char* pcSecretFile, char* pcPublicFile, char* pcPassword);
        bool                          Open(char* pcSecretFile, char* pcPublicFile, char* pcPassword);
        bool                          ReadPublic(char* pcFile) { return OpenPublic(pcFile); };
    };
}
