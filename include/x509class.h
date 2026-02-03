#pragma once
#include "SequenceReader.h"
#include <vector>
#include "Utils.h"
#include "Buffer.h"

using namespace std;

namespace ReiazDean {
	class x509AlternateName;
	class x509CRLDistributionPoint;
	class TBSCertificate;
	class Certificate;
	//*************************************************
	//
	//CLASS x509AlternateName
	//
	//*************************************************
	class x509AlternateName {
		friend class TBSCertificate;
		friend class Certificate;
		//************   Cons/Destruction   ***********
	protected:
		x509AlternateName();
	public:
		x509AlternateName(const Buffer& bValue);
		x509AlternateName(const x509AlternateName&);
		x509AlternateName(x509AlternateName&&) = delete;
		virtual ~x509AlternateName();
		//************ Instance Attributes  ****************
	private:
	protected:
		Buffer                  m_asnOID;
		Buffer                  m_asnObject;
		int8_t                  m_choice;
		int8_t                  m_tag;

	protected:
		bool                    Initialize(Buffer& bValue);
		bool                    Parse(Buffer& bValue);
	public:
		x509AlternateName&      operator=(const x509AlternateName& original);
		x509AlternateName&      operator=(x509AlternateName&& original) = delete;
		Buffer&                 GetOID() { return m_asnOID; };
		Buffer&                 GetAsnObject() { return m_asnObject; };
		void                    PrintSAN(FILE* fp);
	};

	//*************************************************
	//
	//CLASS x509CRLDistributionPoint
	//
	//*************************************************
	class x509CRLDistributionPoint {
		friend class TBSCertificate;
		friend class Certificate;
		//************   Cons/Destruction   ***********
	private:
		x509CRLDistributionPoint();
	public:
		x509CRLDistributionPoint(const Buffer& bValue);
		x509CRLDistributionPoint(const x509CRLDistributionPoint&);
		x509CRLDistributionPoint(x509CRLDistributionPoint&&) = delete;
		virtual ~x509CRLDistributionPoint();
		//************ Instance Attributes  ****************
	private:
	protected:
		std::vector<Buffer>   m_CRLDistPointNames;
		
	protected:
		bool                  IsStringChoice(const Buffer& bCDP);
		bool                  IsGeneralName(const Buffer& bCDP);
		bool                  IsDistPointName(const Buffer& bCDP);
		bool                  HasReasonCode(const Buffer& bCDP);
		bool                  ParseCDP(const Buffer& bCDP);
		bool                  GetLdapName(Buffer& bOut);
	public:
		x509CRLDistributionPoint& operator=(const x509CRLDistributionPoint& original);
		x509CRLDistributionPoint& operator=(x509CRLDistributionPoint&& original) = delete;
	};

	//*************************************************
	//
	//CLASS x509AIADistributionPoint
	//
	//*************************************************
	class x509AIADistributionPoint {
		friend class TBSCertificate;
		friend class Certificate;
		//************   Cons/Destruction   ***********
	private:
		x509AIADistributionPoint();
	public:
		x509AIADistributionPoint(const Buffer& bValue);
		x509AIADistributionPoint(const x509AIADistributionPoint&);
		x509AIADistributionPoint(x509AIADistributionPoint&&) = delete;
		virtual ~x509AIADistributionPoint();
		//************ Instance Attributes  ****************
	private:
	protected:
		std::vector<Buffer>   m_AIADistPointNames;

	protected:
		bool                  ParseAIA(const Buffer& bAIA);
		bool                  GetLdapName(Buffer& bOut);
	public:
		x509AIADistributionPoint& operator=(const x509AIADistributionPoint& original);
		x509AIADistributionPoint& operator=(x509AIADistributionPoint&& original) = delete;
	};

	//*************************************************
	//
	//CLASS TBSCertificate
	//
	//*************************************************
	class TBSCertificate {
		friend class Certificate;
		//************   Cons/Destruction   ***********
	protected:
		TBSCertificate();
	public:
		TBSCertificate(const Buffer& bValue);
		TBSCertificate(const TBSCertificate&) = delete;
		TBSCertificate(TBSCertificate&&) = delete;
		~TBSCertificate();

		//************   Class Attributes   ****************
	private:
	public:
		//************   Class Methods   *******************
	private:
	public:
		//************ Instance Attributes  ****************
	private:
		bool                    m_IsOkay;
		Buffer                  m_version;
		Buffer                  m_serialNum;
		Buffer                  m_SignatureOID;
		Buffer                  m_Issuer;
		Buffer                  m_Validity;
		Buffer                  m_notBefore;
		Buffer                  m_notAfter;
		Buffer                  m_Subject;
		Buffer                  m_PublicKeyInfo;
		Buffer                  m_IssuerUID;
		Buffer                  m_SubjectUID;
		std::vector<std::shared_ptr<x509AlternateName>> m_SubjectAlternateNames;
		std::vector<std::shared_ptr<x509CRLDistributionPoint>> m_CRLDistPoints;
		std::vector<std::shared_ptr<x509AIADistributionPoint>> m_AIADistPoints;

		//************ Instance Methods  ****************
	private:
		bool                    Initialize(const Buffer& bValue);
		bool                    ParseCDPs(const Buffer& bCDPs);
		bool                    ParseAIA(const Buffer& bAIA);
		bool                    ReadOptionals(SequenceReaderX& seq);
		time_t                  Start() { return AsTime_t(m_notBefore); };
		time_t                  End() { return AsTime_t(m_notAfter); };

	public:
		TBSCertificate&         operator=(const TBSCertificate& original);
		TBSCertificate&         operator=(TBSCertificate&& original) = delete;
		Buffer&                 GetPublicKeyInfo() { return m_PublicKeyInfo; };
		Buffer&                 GetSubject() { return m_Subject; };
		Buffer&                 GetSerialNumber() { return m_serialNum; };
		Buffer&                 GetIssuer() { return m_Issuer; };
		Buffer&                 GetStart() { return m_notBefore; };
		Buffer&                 GetEnd() { return m_notAfter; };
		std::vector<std::shared_ptr<x509CRLDistributionPoint>>&
			                    GetCRLDistPoints() { return m_CRLDistPoints; };
		bool                    GetLdapCDP(Buffer& bOut);
		bool                    GetLdapAIA(Buffer& bOut);
		bool                    GetUPNSubjectAltName(Buffer& bOut);
		bool                    IsValid();
		void                    PrintSANs(FILE* fp);
		void                    PrintOn(FILE* fp);
		bool                    IsOkay() { return m_IsOkay; };

	};

	//*************************************************
	//
	//CLASS Certificate
	//
	//*************************************************
	class Certificate {
		friend class x509AlternateName;
		friend class TBSCertificate;
		//************   Cons/Destruction   ***********
	protected:
	public:
		Certificate();
		Certificate(const Buffer& bValue);
		Certificate(const Certificate&) = delete;
		Certificate(Certificate&&) = delete;
		~Certificate();

		//************   Class Attributes   ****************
	private:
	public:
		//************   Class Methods   *******************
	private:
	public:
		//************ Instance Attributes  ****************
	private:
		TBSCertificate            m_TBSCertificate;
		Buffer                    m_SignatureOID;
		Buffer                    m_Signature;
		Buffer                    m_Value;
		bool                      m_Valid;

		//************ Instance Methods  ****************
	private:
		bool                      Initialize(const Buffer& bValue);
		
	public:
		Certificate&              operator=(const Certificate& original);
		Certificate&              operator=(Certificate&& original) = delete;
		void                      PrintSANs(FILE* fp);
		const Buffer&             GetValue() { return m_Value; };
		bool                      IsValid();
		bool                      GetUPNSubjectAltName(Buffer& bOut);
		bool                      GetPublicKeyInfo(Buffer& bOut);
		bool                      GetSubject(Buffer& bOut);
		bool                      GetSerialNumber(Buffer& bOut);
		bool                      GetIssuer(Buffer& bOut);
		bool                      GetStart(Buffer& bOut);
		bool                      GetEnd(Buffer& bOut);
		bool                      GetCRLDistPoints(std::vector<std::shared_ptr<x509CRLDistributionPoint>>& cdp);
		bool                      GetLdapCDP(Buffer& bOut) { return m_TBSCertificate.GetLdapCDP(bOut); };
		bool                      GetLdapAIA(Buffer& bOut) { return m_TBSCertificate.GetLdapAIA(bOut); };
		void                      PrintOn(FILE* fp) { return m_TBSCertificate.PrintOn(fp); };
		bool                      IsOkay() { return m_TBSCertificate.IsOkay(); };
	};
}

