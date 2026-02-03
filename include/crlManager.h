#pragma once
#include <mutex>
#include <condition_variable>
#include <tuple>
#include <vector>
#include "SequenceReader.h"
#include "Buffer.h"
#include "crlClass.h"
#include "x509class.h"

using namespace std;
using std::mutex;
using std::condition_variable;
using std::tuple;
using std::vector;

namespace ReiazDean {
#define NUM_REVOKED_BUCKETS  100

	//*************************************************
	//
	//CLASS CRLManager
	//
	//*************************************************
	class CRLManager {
		//************   Cons/Destruction   ***********
	private:
		CRLManager() {};
		~CRLManager() {};
	protected:
	public:
		CRLManager(const CRLManager&) = delete;
		CRLManager(CRLManager&&) = delete;

		//************   Class Attributes   ****************
	private:
		static mutex s_MutexVar;
		static condition_variable s_ConditionVar;
		static Buffer s_LatestCRL;
		static time_t s_LastCRLtime;
		static vector<Buffer> s_RevokedClientCertSNs[NUM_REVOKED_BUCKETS];
	public:
		//************   Class Methods   *******************
	private:
		static int WhichBucket(const Buffer& bSN);
		static void PersistRevokedSNs();
		static bool IsRevokedSNCached(const Buffer& bSN);
		static void LoadRevokedSNs();
	public:
		static void Initialize();
		static void RememberRevokedSN(const Buffer& bSN);
		static bool IsCertificateRevoked(const Buffer& bCert);
		//************ Instance Attributes  ****************
	private:
		//************ Instance Methods  ****************
	private:
		
	public:
		CRLManager& operator=(const CRLManager& original) = delete;
		CRLManager& operator=(CRLManager&& original) = delete;
	};
}

