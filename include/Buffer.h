#pragma once
#ifdef OS_WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif
#include <string>
#include <mutex>
#include <stdint.h>
#include "Types.h"
#include "MemoryPool.h"

#define MY_MAX_BUFFER_SZ    0x20000000

using std::mutex;
using std::string;
using std::unique_ptr;

namespace ReiazDean {
    class Buffer {
        //************   Cons/Destruction   ***************
    private:
    protected:
    public:
        Buffer();
        Buffer(size_t size);
        Buffer(Buffer&& original) noexcept;
        Buffer(const Buffer &original);
        Buffer(void* data, size_t size);
        Buffer(string &s);
        Buffer(uint8_t* data, size_t size) : Buffer((void*)data, size) {};
        Buffer(int8_t* data, size_t size) : Buffer((void*)data, size) {};
        Buffer(char* data, size_t size) : Buffer((void*)data, size) {};
        virtual ~Buffer();

        //************   Class Attributes   ****************
    private:
        static MemoryPoolManager MyMemPoolManager;
    protected:
    public:

        //************   Class Methods   *******************
    private:
    protected:
    public:
        static void Startup();
        static void Finishup();

        //************ Instance Attributes  ****************
    private:
        mutex                          myMutex;
        bool                           myPagesLocked;
        unique_ptr<MemoryBlock>        myMemoryBlock;
    protected:

    public:

        //************ Instance Methods  *******************
    private:
    protected:
        size_t              append(void* pVoid, size_t size);
        size_t              prepend(void* pVoid, size_t size);
        void                clear();
        void                lockPages();
        void                unlockPages();
    public:
        Buffer&             operator=(const Buffer &original);
        Buffer&             operator=(Buffer&& original) noexcept;
        int8_t&             operator[](size_t i);
        uint32_t            Size();
        bool                Equals(void* pVoid, size_t size);
        size_t              Append(void* pVoid, size_t size);
        size_t              Append(const Buffer &b);
        size_t              Prepend(void* pVoid, size_t size);
        size_t              Prepend(const Buffer& b);
        void                ASN1Wrap(uint8_t tag);
        void                LockPages();
        void                UnlockPages();
        void*               Memory();
        bool                IsInvalid() { return Memory() == INVALID_BUFFER; };
        bool                IsValid() { return !IsInvalid(); };
        void                Clear();
        void                NullTerminate();
        void                NullTerminate_w();
        void                EOLN();
        void                EOLN_w();
        void                Tab();
        void                Tab_w();
        void                Reverse();
        void                AssertIntegerPositivity();
        void                Finalize();

        operator char *()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size == 0) {
                throw("Invalid memory block size!");
            }
            return (char*)myMemoryBlock->memory;
        }

        operator int8_t *()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size == 0) {
                throw("Invalid memory block size!");
            }
            return (int8_t*)myMemoryBlock->memory;
        }

        operator int32_t* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(int32_t)) {
                throw("Invalid memory block size!");
            }
            return (int32_t*)myMemoryBlock->memory;
        }

        operator uint32_t* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(uint32_t)) {
                throw("Invalid memory block size!");
            }
            return (uint32_t*)myMemoryBlock->memory;
        }

        operator size_t* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(size_t)) {
                throw("Invalid memory block size!");
            }
            return (size_t*)myMemoryBlock->memory;
        }

        operator uint8_t *()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size == 0) {
                throw("Invalid memory block size!");
            }
            return (uint8_t*)myMemoryBlock->memory;
        }

        operator void *()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size == 0) {
                throw("Invalid memory block size!");
            }
            return (void*)myMemoryBlock->memory;
        }

        operator CommandHeader *()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(CommandHeader)) {
                throw("Invalid memory block size!");
            }
            return (CommandHeader*)myMemoryBlock->memory;
        }

        operator ResponseHeader *()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(ResponseHeader)) {
                throw("Invalid memory block size!");
            }
            return (ResponseHeader*)myMemoryBlock->memory;
        }

        operator AuthorizationRequest*()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(AuthorizationRequest)) {
                throw("Invalid memory block size!");
            }
            return (AuthorizationRequest*)myMemoryBlock->memory;
        }

        operator AuthorizationResponse* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(AuthorizationResponse)) {
                throw("Invalid memory block size!");
            }
            return (AuthorizationResponse*)myMemoryBlock->memory;
        }

        operator Mandatory_AC* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(Mandatory_AC)) {
                throw("Invalid memory block size!");
            }
            return (Mandatory_AC*)myMemoryBlock->memory;
        }

        operator ThreadArgs* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(ThreadArgs)) {
                throw("Invalid memory block size!");
            }
            return (ThreadArgs*)myMemoryBlock->memory;
        }

        operator wchar_t* ()
        {
            std::unique_lock<std::mutex> mlock(myMutex);
            if (!myMemoryBlock || !myMemoryBlock->memory) {
                throw("Invalid memory block!");
            }
            if (myMemoryBlock->size < sizeof(wchar_t)) {
                throw("Invalid memory block size!");
            }
            return (wchar_t*)myMemoryBlock->memory;
        }
    };
}
