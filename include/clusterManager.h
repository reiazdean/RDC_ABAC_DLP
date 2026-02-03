#pragma once
#include <mutex>
#include <condition_variable>
#include <tuple>
#include <vector>
#include "Buffer.h"

using namespace std;
using std::mutex;
using std::condition_variable;
using std::tuple;
using std::vector;

namespace ReiazDean {
#define MAX_CLUSTER_MEMBERS 8

	//*************************************************
	//
	//CLASS ClusterManager
	//
	//*************************************************
	class ClusterManager {
		//************   Cons/Destruction   ***********
	private:
	protected:
		ClusterManager();
		~ClusterManager() {};
	public:
		ClusterManager(const ClusterManager&) = delete;
		ClusterManager(ClusterManager&&) = delete;

		//************   Instance Attributes   ****************
	protected:
		mutex                          m_MutexVar;
		condition_variable             m_ConditionVar;
		vector<Buffer>                 m_Members;
		vector<Buffer>                 m_FailedMembers;
		Buffer                         m_HostName;
		int                            m_Current;
	public:
		//************   Instance Methods   *******************
	private:
	protected:
		bool IsMember(char* pcMbr);
		bool IsFailedMember(char* pcMbr);
		virtual bool WhereTo(Buffer& bLocation) = 0;
		virtual bool WhereFrom(Buffer& bLocation) = 0;
		virtual bool Persist() = 0;
	public:
		ClusterManager& operator=(const ClusterManager& original) = delete;
		ClusterManager& operator=(ClusterManager&& original) = delete;
		bool ReadMemberFile(Buffer& bMbrs);
		bool LoadMembers();
		void FailMember(char* pcMbr);
		void RecoverMember(char* pcMbr);
		bool AddMember(char* pcMbr);
		bool RemoveMember(char* pcMbr);
		void GetMembers(Buffer& bMbrs);
		bool RoundRobin(Buffer& bMbr);
	};
}

