#pragma once
#include <mutex>
#include <condition_variable>
#include <string>
#include <vector>
#include <thread>
#include "TLSServerContext.h"
#include "Utils.h"
#include "DocHandler.h"

using std::vector;
using std::pair;
using std::string;
using std::thread;
using std::mutex;
using std::condition_variable;

namespace ReiazDean {
    class Authorization {
        friend class TLSServerContext;
        //************   Cons/Destruction   ***************
    private:
    protected:
        Authorization();
    public:
        Authorization(const Authorization&) = delete;
        Authorization(Authorization&&) = delete;
        virtual ~Authorization();

        //************   Class Attributes   ****************
    private:
    protected:
    public:
        
        //************   Class Methods   *******************
    private:
    protected:

    public:

        //************ Instance Attributes  ****************
    private:
        
    public:

        //************ Instance Methods  *******************
    private:
    protected:
        Responses                 IsAuthorized(const Mandatory_AC& userMac,
                                  const Mandatory_AC& docMac);
    public:
        Authorization&            operator=(const Authorization& original) = delete;
        Authorization&            operator=(Authorization&& original) = delete;
        Responses                 CanDownlaod(Mandatory_AC& userMac,
                                              DocHandler& dh,
                                              uint16_t computerMLS);
        Responses                 CanPublish(Buffer& bPN,
                                             Mandatory_AC& userMac,
                                             DocHandler& dh,
                                             uint16_t computerMLS);
        Responses                 GetDecryptionKeyForUser(Mandatory_AC& userMac,
                                                          AuthorizationRequest* pAR,
                                                          AuthorizationResponse& ar);
        Responses                 GetEncryptionKeyForUser(Mandatory_AC& userMac,
                                                          AuthorizationResponse& ar);
    };
}

#pragma once
