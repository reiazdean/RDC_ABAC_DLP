/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "pch.h"
#include <stdlib.h>
#include <stdio.h>
#include "Utils.h"
#include "Buffer.h"

using namespace ReiazDean;

void Buffer::Startup() {
}

void Buffer::Finishup() {
    //MyMemPoolManager.Finalize();
}

Buffer::Buffer() {
    myMemoryBlock = nullptr;
    myPagesLocked = false;
}

Buffer::Buffer(size_t size) : Buffer() {
    if (size > MY_MAX_BUFFER_SZ) {
        throw("Invalid memory block size!");
    }

    myMemoryBlock = MyMemPoolManager.GetMemoryBlock((uint32_t)size);
    if (!myMemoryBlock) {
        throw("Invalid memory block!");
    }
}

Buffer::Buffer(void* data, size_t size) : Buffer(size) {
    myMemoryBlock->Append((int8_t*)data, (uint32_t)size);
}

Buffer::Buffer(string &s) : Buffer((void*)s.c_str(), (size_t)s.size()) {
}

Buffer::Buffer(const Buffer& original) : Buffer() {
    if (original.myMemoryBlock) {
        myMemoryBlock = MyMemPoolManager.GetMemoryBlock(original.myMemoryBlock->size);
        if (!myMemoryBlock) {
            throw("Invalid memory block!");
        }
        append((void*)original.myMemoryBlock->memory, original.myMemoryBlock->written);
    }
}

Buffer::Buffer(Buffer&& original) noexcept : Buffer() {
    if (original.myMemoryBlock) {
        myMemoryBlock = std::move(original.myMemoryBlock);
        original.myMemoryBlock = nullptr;
    }
}

Buffer::~Buffer() {
    Finalize();
}

uint32_t Buffer::Size() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        return myMemoryBlock->written;
    }
    return 0;
}

void Buffer::clear() {
    if (myMemoryBlock) {
        unlockPages();
        myMemoryBlock->Zeroize();
    }
}

void Buffer::Clear() {
    std::unique_lock<std::mutex> mlock(myMutex);
    clear();
}

void Buffer::Finalize() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        unlockPages();
        MyMemPoolManager.ReleaseMemory(std::move(myMemoryBlock));
        myMemoryBlock = nullptr;
    }
}

Buffer& Buffer::operator=(const Buffer& original) {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        unlockPages();
        MyMemPoolManager.ReleaseMemory(std::move(myMemoryBlock));
        myMemoryBlock = nullptr;
    }

    if (original.myMemoryBlock) {
        myMemoryBlock = MyMemPoolManager.GetMemoryBlock(original.myMemoryBlock->size);
        if (!myMemoryBlock) {
            throw("Invalid memory block!");
        }
        append((void*)original.myMemoryBlock->memory, original.myMemoryBlock->written);
    }

    return *this;
}

Buffer& Buffer::operator=(Buffer&& original) noexcept {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        unlockPages();
        MyMemPoolManager.ReleaseMemory(std::move(myMemoryBlock));
        myMemoryBlock = nullptr;
    }

    if (original.myMemoryBlock) {
        myMemoryBlock = std::move(original.myMemoryBlock);
        original.myMemoryBlock = nullptr;
    }

    return *this;
}

int8_t& Buffer::operator[](size_t i) {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (!myMemoryBlock) {
        throw("Invalid memory block!");
    }

    if (i >= myMemoryBlock->size) {
        throw("Out of range!");
    }

    return myMemoryBlock->memory[i];
}

bool Buffer::Equals(void* pVoid, size_t sz) {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock && pVoid && (sz == myMemoryBlock->written)) {
        return (memcmp(pVoid, (void*)myMemoryBlock->memory, myMemoryBlock->written) == 0);
    }
    return false;
}

size_t Buffer::append(void* pVoid, size_t size) {
    if (size > MY_MAX_BUFFER_SZ) {
        throw("Invalid memory block size!");
    }

    if (!myMemoryBlock) {
        return 0;
    }
    else if (myPagesLocked) {
        return 0;
    }
    else if (size <= 0) {
        return 0;
    }
    else if (!pVoid) {
        return 0;
    }

    if (myMemoryBlock->size >= (myMemoryBlock->written + size + sizeof(WCHAR))) {
        myMemoryBlock->Append((int8_t*)pVoid, (uint32_t)size);
    }
    else {
        unique_ptr<MemoryBlock> ptr = MyMemPoolManager.GetMemoryBlock(myMemoryBlock->written + (uint32_t)size + sizeof(WCHAR));
        if (!ptr) {
            throw("Invalid memory pool resource!");
        }
        ptr->Append(myMemoryBlock, myMemoryBlock->written);
        MyMemPoolManager.ReleaseMemory(std::move(myMemoryBlock));
        ptr->Append((int8_t*)pVoid, (uint32_t)size);
        myMemoryBlock = std::move(ptr);
    }
    
    return myMemoryBlock->written;
}

size_t Buffer::Append(void* pVoid, size_t size) {
    try {
        std::unique_lock<std::mutex> mlock(myMutex);
        if (!myMemoryBlock) {
            myMemoryBlock = MyMemPoolManager.GetMemoryBlock((uint32_t)size);
            if (!myMemoryBlock) {
                throw("Invalid memory block!");
            }
        }
        return append(pVoid, size);
    }
    catch (...) {
        throw("Invalid memory block!");
    }
}

size_t Buffer::Append(const Buffer& b) {
    try {
        std::unique_lock<std::mutex> mlock(myMutex);
        if (!b.myMemoryBlock) {
            return 0;
        }

        if (!myMemoryBlock) {
            myMemoryBlock = MyMemPoolManager.GetMemoryBlock(b.myMemoryBlock->size);
            if (!myMemoryBlock) {
                throw("Invalid memory block!");
            }
        }

        return append((void*)b.myMemoryBlock->memory, b.myMemoryBlock->written);
    }
    catch (...) {
        throw("Invalid memory block!");
    }
}

size_t Buffer::prepend(void* pVoid, size_t size) {
    unique_ptr<MemoryBlock> ptr = nullptr;

    if (size > MY_MAX_BUFFER_SZ) {
        throw("Invalid memory block size!");
    }
    
    if (!myMemoryBlock) {
        return 0;
    }
    else if (myPagesLocked) {
        return 0;
    }
    else if (size <= 0) {
        return 0;
    }
    else if (!pVoid) {
        return 0;
    }
    
    ptr = MyMemPoolManager.GetMemoryBlock(myMemoryBlock->written + (uint32_t)size);
    if (!ptr) {
        throw("Invalid memory pool resource!");
    }

    ptr->Append((int8_t*)pVoid, (uint32_t)size);
    if (myMemoryBlock->written > 0) {
        ptr->Append(myMemoryBlock, myMemoryBlock->written);
    }
    MyMemPoolManager.ReleaseMemory(std::move(myMemoryBlock));
    myMemoryBlock = std::move(ptr);

    return myMemoryBlock->written;
}

size_t Buffer::Prepend(void* pVoid, size_t size) {
    try {
        std::unique_lock<std::mutex> mlock(myMutex);
        if (!myMemoryBlock) {
            myMemoryBlock = MyMemPoolManager.GetMemoryBlock((uint32_t)size);
            if (!myMemoryBlock) {
                throw("Invalid memory block!");
            }
        }
        return prepend(pVoid, size);
    }
    catch (...) {
        throw("Invalid memory block!");
    }
}

size_t Buffer::Prepend(const Buffer& b) {
    try {
        std::unique_lock<std::mutex> mlock(myMutex);
        if (!b.myMemoryBlock) {
            return 0;
        }

        if (!myMemoryBlock) {
            myMemoryBlock = MyMemPoolManager.GetMemoryBlock(b.myMemoryBlock->size);
            if (!myMemoryBlock) {
                throw("Invalid memory block!");
            }
        }
        
        return prepend((void*)b.myMemoryBlock->memory, b.myMemoryBlock->written);
    }
    catch (...) {
        throw("Invalid memory block!");
    }
}

void* Buffer::Memory() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        return (void*)myMemoryBlock->memory;
    }
    return (void*)INVALID_BUFFER;
}

void Buffer::lockPages() {
    if (!myPagesLocked) {
#ifdef OS_WIN32
        VirtualLock((void*)myMemoryBlock->memory, myMemoryBlock->written);
#else
        mlock2((void*)myMemoryBlock->memory, myMemoryBlock->written, 0);
#endif
        myPagesLocked = true;
    }
}

void Buffer::LockPages() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        lockPages();
    }
}

void Buffer::unlockPages() {
    if (myPagesLocked) {
#ifdef OS_WIN32
        VirtualUnlock((void*)myMemoryBlock->memory, myMemoryBlock->written);
#else
        munlock((void*)myMemoryBlock->memory, myMemoryBlock->written);
#endif
        myPagesLocked = false;
    }
}

void Buffer::UnlockPages() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        unlockPages();
    }
}

void Buffer::NullTerminate() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        append((void*)"\0", 1);
    }
}

void Buffer::NullTerminate_w() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        append((void*)L"\0", sizeof(wchar_t));
    }
}

void Buffer::EOLN() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        append((void*)"\n", 1);
    }
}

void Buffer::EOLN_w() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        append((void*)L"\n", sizeof(wchar_t));
    }
}

void Buffer::Tab() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        append((void*)"\t", 1);
    }
}

void Buffer::Tab_w() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        append((void*)L"\t", sizeof(wchar_t));
    }
}

void Buffer::Reverse() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (myMemoryBlock) {
        myMemoryBlock->Reverse();
    }
}

void Buffer::ASN1Wrap(uint8_t tag) {
    uint8_t   TL[6];
    uint8_t   lenOfLen;
    size_t  sz = 0;
    std::unique_lock<std::mutex> mlock(myMutex);
    if (!myMemoryBlock || !myMemoryBlock->memory) {
        return;
    }

    sz = myMemoryBlock->written;

#ifndef _BIG_ENDIAN
    ReverseMemory((uint8_t*)&sz, sizeof(sz));
#endif

    if (myMemoryBlock->written < 0x80)
        lenOfLen = 0x0;
    else if (myMemoryBlock->written < 0x100)
        lenOfLen = 0x1;
    else if (myMemoryBlock->written < 0x10000)
        lenOfLen = 0x2;
    else if (myMemoryBlock->written < 0x1000000)
        lenOfLen = 0x3;
    else
        lenOfLen = 0x4;

    memset(TL, 0, sizeof(TL));
    TL[0] = tag;
    if (lenOfLen == 0) {
        TL[1] = (uint8_t)myMemoryBlock->written;
    }
    else {
        uint8_t* pC = (uint8_t*)&sz;
        TL[1] = 0x80 | lenOfLen;
        memcpy(&TL[2], pC + sizeof(sz) - lenOfLen, lenOfLen);
    }

    prepend(TL, (size_t)lenOfLen + 2);
}

void Buffer::AssertIntegerPositivity() {
    std::unique_lock<std::mutex> mlock(myMutex);
    if (!myMemoryBlock || !myMemoryBlock->memory) {
        return;
    }
    else {
        uint8_t* pc = (uint8_t*)myMemoryBlock->memory;
        uint8_t c = pc[0];
        if ((c >> 7) == 0x1) {
            prepend((void*)"\0", 1);//assert positivity
        }
    }
}
