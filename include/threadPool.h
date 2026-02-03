#pragma once
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include "Buffer.h"

namespace ReiazDean {

#define                MAX_POOLED_THREADS                100

	using std::vector;
	using std::map;
	using std::thread;
	using std::mutex;
	using std::condition_variable;
	using std::function;
	using std::unique_ptr;
	using std::shared_ptr;

	//*************************************************
	//
	//CLASS threadPool
	//
	//*************************************************
	class threadPool {
		//************   Cons/Destruction   ***********
	protected:
		threadPool() {};
	public:
		threadPool(const threadPool&) = delete;
		threadPool(threadPool&&) = delete;
		virtual ~threadPool() {};
		//************ Instance Attributes  ****************
	private:
	protected:
		static vector<thread*>                  joiningThreads;

	private:
		static ThreadArgs                        Targs[MAX_POOLED_THREADS];
		static vector<uint16_t>                  freeArgs;
		static mutex                             mutexVar;
		static condition_variable                conditionVar;
		static bool                              isIntitialized;
		static bool                              isFinalized;
		static void                              joinThreads();
		static void                              threadProc(uint16_t indexTA);
	public:
		static void                              Initialize();
		static void                              Finalize();
		static void                              queueThread(void* threadFct, void* args);
		threadPool&                              operator=(const threadPool& original) = delete;
		threadPool&                              operator=(threadPool&& original) = delete;

	};
}

