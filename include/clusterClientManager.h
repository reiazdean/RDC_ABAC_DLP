#pragma once
#include "clusterManager.h"

namespace ReiazDean {
	//*************************************************
	//
	//CLASS ClusterClientManager
	//
	//*************************************************
	class ClusterClientManager : public ClusterManager {
		//************   Cons/Destruction   ***********
	protected:
		ClusterClientManager();
		~ClusterClientManager() {};
	protected:
	public:
		ClusterClientManager(const ClusterClientManager&) = delete;
		ClusterClientManager(ClusterClientManager&&) = delete;
		static ClusterClientManager& GetInstance() {
			return TheClusterClientManager;
		};
		//************   Instance Attributes   ****************
	private:
		static ClusterClientManager TheClusterClientManager;
		int m_Current;
	public:
		//************   Instance Methods   *******************
		static void* ClusterClientRecoveryProc(void* arg);
	private:
		virtual bool WhereTo(Buffer& bLocation);
		virtual bool WhereFrom(Buffer& bLocation);
		virtual bool Persist();
	public:
		ClusterClientManager& operator=(const ClusterClientManager& original) = delete;
		ClusterClientManager& operator=(ClusterClientManager&& original) = delete;
		void UpdateMembers(Buffer& bMbrs);
		bool IsSandboxedClient();
	};
}

