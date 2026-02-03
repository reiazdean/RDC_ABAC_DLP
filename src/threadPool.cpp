/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "threadPool.h"

using namespace ReiazDean;

mutex                      threadPool::mutexVar;
condition_variable         threadPool::conditionVar;
vector<thread*>            threadPool::joiningThreads;
ThreadArgs                 threadPool::Targs[MAX_POOLED_THREADS];
vector<uint16_t>           threadPool::freeArgs;
bool                       threadPool::isIntitialized = false;
bool                       threadPool::isFinalized = false;

void threadPool::Initialize() {
    std::unique_lock<std::mutex> mlock(mutexVar);
    if (isIntitialized) {
        return;
    }
    isIntitialized = true;
    for (uint16_t i = 0; i < MAX_POOLED_THREADS; i++) {
        freeArgs.push_back(i);
        Targs[i].threadFct = nullptr;
        Targs[i].args = nullptr;
        Targs[i].pThread = nullptr;
    }
    joiningThreads.reserve(MAX_POOLED_THREADS);
}

void threadPool::Finalize() {
    std::unique_lock<std::mutex> mlock(mutexVar);
    isFinalized = true;
    while (freeArgs.size() < MAX_POOLED_THREADS) {
        conditionVar.wait_for(mlock, std::chrono::seconds(1));
    }

    joinThreads();
    freeArgs.clear();
}

void threadPool::joinThreads() {
    for (int i = 0; i < joiningThreads.size(); i++)
    {
        thread* pThread = joiningThreads[i];
        if (pThread) {
            pThread->join();
            delete pThread;
        }
    }

    joiningThreads.clear();
}

void threadPool::queueThread(void* threadFct, void* args) {
    std::unique_lock<std::mutex> mlock(mutexVar);
    while (!isFinalized)
    {
        joinThreads();
        if (freeArgs.size() > 0)
        {
            uint16_t idx = freeArgs.back();
            freeArgs.pop_back();
            Targs[idx].threadFct = (threadProcedure*)threadFct;
            Targs[idx].args = args;
            Targs[idx].pThread = new thread(threadProc, idx);
            return;
        }
        else
        {
            conditionVar.wait_for(mlock, std::chrono::seconds(1));
            //conditionVar.wait(mlock);
        }
    }
   
    return;
}

void threadPool::threadProc(uint16_t indexTA) {
    threadProcedure* threadFct = nullptr;

    threadFct = Targs[indexTA].threadFct;
    if (threadFct) {
        threadFct(Targs[indexTA].args);
    }

    {
        std::unique_lock<std::mutex> mlock(mutexVar);
        freeArgs.push_back(indexTA);
        joiningThreads.push_back(Targs[indexTA].pThread);
        Targs[indexTA].threadFct = nullptr;
        Targs[indexTA].args = nullptr;
        Targs[indexTA].pThread = nullptr;
        conditionVar.notify_all();
    }
}

