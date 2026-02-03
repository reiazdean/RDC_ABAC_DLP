#pragma once
#include "clusterManager.h"

namespace ReiazDean {
	//*************************************************
	//
	//CLASS ClusterServiceManager
	//
	//*************************************************
	class ClusterServiceManager : public ClusterManager {
		//************   Cons/Destruction   ***********
	private:
	protected:
		ClusterServiceManager() {};
		~ClusterServiceManager() {};
	public:
		ClusterServiceManager(const ClusterServiceManager&) = delete;
		ClusterServiceManager(ClusterServiceManager&&) = delete;
		static ClusterServiceManager& GetInstance() {
			return TheClusterServiceManager;
		};

		//************   Class Attributes   ****************
	private:
		static ClusterServiceManager TheClusterServiceManager;
		Buffer m_Secrets;
	public:
		//************   Class Methods   *******************
	private:
		bool CopyConfigFilesToClusterConfig();
		bool CopyConfigFilesFromClusterConfig(char* path);
		virtual bool WhereTo(Buffer& bLocation);
		virtual bool WhereFrom(Buffer& bLocation);
		virtual bool Persist();
	public:
		ClusterServiceManager& operator=(const ClusterServiceManager& original) = delete;
		ClusterServiceManager& operator=(ClusterServiceManager&& original) = delete;
		void SetSecrets(Buffer bSecrets);
		Buffer GetSecrets();
		bool CreateCluster();
		bool JoinCluster(char* path);
		bool UnjoinCluster();
		bool PollMembersForSecrets(Buffer& bPwd);
		//************ Instance Attributes  ****************
	private:
		//************ Instance Methods  ****************
	private:
		
	public:
	};
}

