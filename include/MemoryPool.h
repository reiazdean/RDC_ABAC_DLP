#pragma once
#include <map>
#include <thread>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
#include "Types.h"

using std::string;
using std::vector;
using std::map;
using std::unique_ptr;
using std::shared_ptr;
using std::mutex;
using std::thread;
using std::condition_variable;

#define        BLOCK_INCREMENT        2
#define        MICRO_BLOCK_SZ         32
#define        NUM_POOLS              20
#define        MICRO_POOL_CNT         1000


constexpr auto INVALID_BUFFER = "#### INVALID ####";

namespace ReiazDean {
    class Buffer;
    class MemoryPoolManager;
    
    struct MemoryBlock {
        MemoryBlock();
        MemoryBlock(const MemoryBlock&) = delete;
        MemoryBlock(MemoryBlock&&) = delete;
        MemoryBlock(uint32_t sz);
        ~MemoryBlock();
        uint32_t size;
        uint32_t written;
        //unique_ptr<int8_t[]> memory;
        int8_t* memory;
        void Append(int8_t* data, uint32_t len);
        void Append(unique_ptr<MemoryBlock>& b, uint32_t len);
        void Reverse();
        void Zeroize();
        //int8_t& operator[](int32_t i) { return memory[i]; };
    };

    class MemoryPool {
        //************   Cons/Destruction   ***************
    private:
        MemoryPool();
    public:
        MemoryPool(uint32_t size, uint16_t maxBlocks);
        MemoryPool(const MemoryPool&) = delete;
        MemoryPool(MemoryPool&&) = delete;
        virtual ~MemoryPool();

        //************   Class Attributes   ****************
    private:
    public:

        //************   Class Methods   *******************
    private:
    protected:
    public:
        //************ Instance Attributes  ****************
    private:
        vector<unique_ptr<MemoryBlock>>     myFreeBlocks;
        uint16_t                            myCreatedBlockCount;
        uint32_t                            mySize;
        uint16_t                            myMaxBlocks;
        mutex                               myMutex;
        condition_variable                  myConditionVar;
        bool                                isFinalized;
    public:

        //************ Instance Methods  *******************
    private:
    public:
        MemoryPool&                         operator=(const MemoryPool& original) = delete;
        MemoryPool&                         operator=(MemoryPool&& original) = delete;
        void                                Finalize();
        unique_ptr<MemoryBlock>             GetMemoryBlock();
        void                                ReleaseMemory(unique_ptr<MemoryBlock>);
        uint64_t                            PrintStat(FILE* fp);
    };

    class MemoryPoolManager {
        friend class Buffer;
        //************   Cons/Destruction   ***************
    public:
        MemoryPoolManager(const MemoryPoolManager&) = delete;
        MemoryPoolManager(MemoryPoolManager&&) = delete;
    private:
        MemoryPoolManager();
    public:
        virtual ~MemoryPoolManager();

        //************   Class Attributes   ****************
    private:
    public:

        //************   Class Methods   *******************
    private:
    protected:
    public:
        //************ Instance Attributes  ****************
    private:
        map<uint32_t, unique_ptr<MemoryPool>>   myMemoryPools;
        mutex                                   myMutex;
    public:

        //************ Instance Methods  *******************
    private:
        
    public:
        MemoryPoolManager&                  operator=(const MemoryPoolManager& original) = delete;
        MemoryPoolManager&                  operator=(MemoryPoolManager&& original) = delete;
        void                                Initialize();
        void                                Finalize();
        unique_ptr<MemoryBlock>             GetMemoryBlock(uint32_t sz);
        void                                ReleaseMemory(unique_ptr<MemoryBlock>);
        void                                PrintStat(FILE* fp);
    };
};


