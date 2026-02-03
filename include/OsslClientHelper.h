#pragma once
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include "Buffer.h"
#include "TLSClientContext.h"

using std::vector;
using std::map;
using std::thread;
using std::mutex;
using std::condition_variable;

namespace ReiazDean {
	//*************************************************
	//
	//CLASS OsslClientHelper
	//
	//*************************************************
	class OsslClientHelper {
		//************   Cons/Destruction   ***********
	protected:
		OsslClientHelper() {};
	public:
		OsslClientHelper(const OsslClientHelper&) = delete;
		OsslClientHelper(OsslClientHelper&&) = delete;
		virtual ~OsslClientHelper() {};
		//************ Instance Attributes  ****************
	private:
	protected:
		static std::vector<std::tuple<TLSClientContext&, Buffer, Buffer, Buffer&, condition_variable&>> Requests;

	private:
		static mutex s_MutexVar;
		static condition_variable s_ConditionVar;
		static bool s_IsIntitialized;
		static bool s_IsFinalized;
	public:
		static void* Initialize(void* args);
		static bool QueueCommand(TLSClientContext& client, Buffer bCmd, Buffer bHost, Buffer& bResp, condition_variable& cv);
	private:
		OsslClientHelper& operator=(const OsslClientHelper& original) = delete;
		OsslClientHelper& operator=(OsslClientHelper&& original) = delete;
		static void Finalize();
		static void Executor();
		static bool ExecuteCmd(TLSClientContext& client, Buffer bCmd, Buffer bHost, Buffer& bResp);
	protected:
		
	};
}
