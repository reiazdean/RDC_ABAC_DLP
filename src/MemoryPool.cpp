/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "pch.h"
#include "Utils.h"
#include "MemoryPool.h"

using namespace ReiazDean;

MemoryBlock::MemoryBlock() {
	size = 0;
	written = 0;
	memory = nullptr;
}

MemoryBlock::MemoryBlock(uint32_t sz) : MemoryBlock() {
	size = sz;
	memory = (int8_t*)calloc(sz, 1);// std::make_unique<int8_t[]>(sz);
}

MemoryBlock::~MemoryBlock() {
	//printf("Freeing MemoryBlock written = %d size = %d\n", written, size);
	if (memory) {
		memset(memory, 0, size);
		free(memory);
		memory = nullptr;
	}
	size = 0;
}

void MemoryBlock::Append(int8_t* data, uint32_t len) {
	if (size >= (written + len)) {
		memcpy(memory + written, data, len);
		written += len;
	}
}

void MemoryBlock::Append(unique_ptr<MemoryBlock>& b, uint32_t len) {
	Append(b->memory, len);
}

void MemoryBlock::Reverse() {
	uint32_t      index;
	uint32_t      transposeIndex;
	uint8_t     bTemp;

	for (index = 0; index < (written / 2); index++)
	{
		transposeIndex = written - (1 + index);

		bTemp = memory[transposeIndex];
		memory[transposeIndex] = memory[index];
		memory[index] = bTemp;
	}

	return;
}

void MemoryBlock::Zeroize() {
	if (memory) {
		memset(memory, 0, size);
		written = 0;
	}
	return;
}

MemoryPool::MemoryPool() {
	myCreatedBlockCount = 0;
	mySize = 0;
	myMaxBlocks = 0;
	isFinalized = false;
}

MemoryPool::MemoryPool(uint32_t size, uint16_t maxBlocks) : MemoryPool() {
	mySize = size;
	myMaxBlocks = maxBlocks;
	myFreeBlocks.reserve(myMaxBlocks);
}

MemoryPool::~MemoryPool() {
	//printf("Freeing MemoryPool used = %d max = %d size = %d\n", myCreatedBlockCount, myMaxBlocks, mySize);
}

unique_ptr<MemoryBlock> MemoryPool::GetMemoryBlock( )
{
	unique_ptr<MemoryBlock> ptr = nullptr;
	std::unique_lock<std::mutex> mlock(myMutex);

	while (!ptr) {
		if (myFreeBlocks.size() > 0) {
			ptr = std::move(myFreeBlocks.back());
			myFreeBlocks.pop_back();
		}
		else if (myCreatedBlockCount < myMaxBlocks) {
			myCreatedBlockCount++;
			ptr = std::make_unique<MemoryBlock>(mySize);
		}
		else {
			//printf("Start Waiting MemoryPool used = %d max = %d size = %d\n", myCreatedBlockCount, myMaxBlocks, mySize);
			myConditionVar.wait(mlock);
			//printf("Done Waiting MemoryPool used = %d max = %d size = %d\n", myCreatedBlockCount, myMaxBlocks, mySize);
		}
	}

	return ptr;
}

void MemoryPool::ReleaseMemory(unique_ptr<MemoryBlock> mem)
{
	std::unique_lock<std::mutex> mlock(myMutex);
	//printf("Releasing MemoryBlock written = %d size = %d\n", mem->written, mem->size);
	if (mem) {
		mem->Zeroize();
		if (!isFinalized) {
			myFreeBlocks.push_back(std::move(mem));
		}
	}
	myConditionVar.notify_all();
}

void MemoryPool::Finalize()
{
	std::unique_lock<std::mutex> mlock(myMutex);
	myFreeBlocks.clear();
	isFinalized = true;
}

uint64_t MemoryPool::PrintStat(FILE* fp)
{
	if (fp) {
		fprintf(fp, "MemoryPool stats: [created = %u] [free = %zu] [max = %u] [size = %u]\n",
			myCreatedBlockCount, myFreeBlocks.size(), myMaxBlocks, mySize);
	}
	return (uint64_t)myCreatedBlockCount * (uint64_t)mySize;
}

////////////////////////////////////////////////////
//////  MemoryPoolManager  ////////////////////////
//////////////////////////////////////////////////

MemoryPoolManager::MemoryPoolManager()
{
	Initialize();
}

void MemoryPoolManager::Initialize()
{
	std::unique_lock<std::mutex> mlock(myMutex);
	if (myMemoryPools.size() == 0) {
		uint32_t sz = MICRO_BLOCK_SZ;
		for (int i = 0; i < NUM_POOLS; i++) {
			uint32_t poolSz = MICRO_POOL_CNT / (i + 1);
			myMemoryPools[sz] = std::make_unique<MemoryPool>(sz, poolSz);
			sz *= BLOCK_INCREMENT;
		}
	}
}

MemoryPoolManager::~MemoryPoolManager()
{
#ifdef _DEBUG
	FILE* fp = f_open_f((char*)"C:\\Users\\Public\\memory.txt", (char*)"wt");
	if (fp) {
		PrintStat(fp);
		fclose(fp);
	}
#endif
	Finalize();
#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif
}

unique_ptr<MemoryBlock> MemoryPoolManager::GetMemoryBlock(uint32_t sz)
{
	unique_ptr<MemoryBlock> ptr = nullptr;

	std::unique_lock<std::mutex> mlock(myMutex);
	for (const auto& pool : myMemoryPools) {
		if (sz <= pool.first) {
			ptr = pool.second->GetMemoryBlock();
			return ptr;
		}
	}

	return ptr;
}

void MemoryPoolManager::ReleaseMemory(unique_ptr<MemoryBlock> mem)
{
	std::unique_lock<std::mutex> mlock(myMutex);
	for (auto& pool : myMemoryPools) {
		if (mem->size == pool.first) {
			pool.second->ReleaseMemory(std::move(mem));
			return;
		}
	}
}

void MemoryPoolManager::Finalize()
{
	std::unique_lock<std::mutex> mlock(myMutex);
	for (auto& pool : myMemoryPools) {
		pool.second->Finalize();
	}
	myMemoryPools.clear();
}

void MemoryPoolManager::PrintStat(FILE* fp)
{
	uint64_t total = 0;
	uint64_t sz = MICRO_BLOCK_SZ;
	if (fp) {
		std::unique_lock<std::mutex> mlock(myMutex);
		printf("\n============================================\n");
		for (const auto& pool : myMemoryPools) {
			total += pool.second->PrintStat(fp);
		}
		fprintf(fp, "Total consumed heap = %I64u bytes\n", total);
		fprintf(fp, "============================================\n");

		total = 0;
		for (uint64_t i = 0; i < NUM_POOLS; i++) {
			uint64_t poolSz = MICRO_POOL_CNT / (i + 1);
			total += (sz * poolSz);
			sz *= BLOCK_INCREMENT;
		}
		fprintf(fp, "Maximum possible heap = %I64u bytes\n", total);
	}
}
