#pragma once
#include <mutex>
#include <vector>
#include "SequenceReader.h"
#include "Buffer.h"

using namespace std;
using std::mutex;

namespace ReiazDean {
	class CrlRevokedSN;
	class TBSCertList;
	class CertificateRL;
	//*************************************************
	//
	//CLASS CrlRevokedSN
	//
	//*************************************************
	class CrlRevokedSN {
		friend class TBSCertList;
		friend class CertificateRL;
		//************   Cons/Destruction   ***********
	protected:
		CrlRevokedSN();
	public:
		CrlRevokedSN(const Buffer& bSN);
		CrlRevokedSN(const CrlRevokedSN&) = delete;
		CrlRevokedSN(CrlRevokedSN&&) = delete;
		virtual ~CrlRevokedSN();
		//************ Instance Attributes  ****************
	private:
	protected:
		Buffer                    m_CertSN;
		Buffer                    m_revocationDate;
		  
	protected:
		bool                      Parse(const Buffer& bSN);
	public:
		CrlRevokedSN& operator=(const CrlRevokedSN& original);
		CrlRevokedSN& operator=(CrlRevokedSN&& original) = delete;
		Buffer&                   GetSN() { return m_CertSN; };
		Buffer&                   GetRevocationDate() { return m_revocationDate; };
		void                      PrintOn(FILE* fp);
	};
	//*************************************************
	//
	//CLASS TBSCertificate
	//
	//*************************************************
	class TBSCertList {
		friend class CertificateRL;
		//************   Cons/Destruction   ***********
	protected:
		TBSCertList();
	public:
		TBSCertList(const Buffer& bValue);
		TBSCertList(const TBSCertList&) = delete;
		TBSCertList(TBSCertList&&) = delete;
		~TBSCertList();

		//************   Class Attributes   ****************
	private:
	public:
		//************   Class Methods   *******************
	private:
	public:
		//************ Instance Attributes  ****************
	private:
		std::vector<std::shared_ptr<CrlRevokedSN>>     m_RevokedSerialNumbers;

		//************ Instance Methods  ****************
	private:
		bool                      Initialize(const Buffer& bValue);
		bool                      ParseSNs(const Buffer& bValue);
		
	public:
		TBSCertList&              operator=(const TBSCertList& original);
		TBSCertList&              operator=(TBSCertList&& original) = delete;
		bool                      IsRevoked(Buffer& bSN);
		void                      RememberRevokedSNs();
		void                      PrintOn(FILE* fp);

	};

	//*************************************************
	//
	//CLASS Certificate
	//
	//*************************************************
	class CertificateRL {
		friend class TBSCertList;
		//************   Cons/Destruction   ***********
	private:
	protected:
	public:
		CertificateRL();
		CertificateRL(const Buffer& bValue);
		CertificateRL(const CertificateRL&) = delete;
		CertificateRL(CertificateRL&&) = delete;
		~CertificateRL();

		//************   Class Attributes   ****************
	private:
	public:
		//************   Class Methods   *******************
	private:
	public:
		//************ Instance Attributes  ****************
	private:
		TBSCertList               m_TBSCertList;
		Buffer                    m_TBSbytes;
		Buffer                    m_SignatureOID;
		Buffer                    m_Signature;
		mutex                     m_Mutex;

		//************ Instance Methods  ****************
	private:
		bool                      Initialize(const Buffer& bValue);
		
	public:
		CertificateRL&            operator=(const CertificateRL& original);
		CertificateRL&            operator=(CertificateRL&& original) = delete;
		bool                      IsRevoked(Buffer& bSN);
		bool                      IsVerified();
		bool                      IsNotVerified() {
			return !IsVerified();
		};
		void                      RememberRevokedSNs() {
			m_TBSCertList.RememberRevokedSNs();
		};
		void                      PrintOn(FILE* fp);
	};
}

