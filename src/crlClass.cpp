/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "Utils.h"
#include "crlClass.h"
#include "crlManager.h"
#include "NdacConfig.h"
#include "TLSContext.h"

using namespace ReiazDean;
//*************************************************
//
//CLASS CrlRevokedSN
//
//*************************************************
CrlRevokedSN::CrlRevokedSN()
{
}

CrlRevokedSN::CrlRevokedSN(const Buffer& bSN) : CrlRevokedSN()
{
	Parse(bSN);
}

CrlRevokedSN::~CrlRevokedSN()
{
}

CrlRevokedSN& CrlRevokedSN::operator=(const CrlRevokedSN& original) {
	m_CertSN = original.m_CertSN;
	m_revocationDate = original.m_revocationDate;
	return *this;
}

bool CrlRevokedSN::Parse(const Buffer& bSN)
{
	try {
		bool   bRc = false;
		SequenceReaderX	snSeq;
		if (snSeq.Initilaize(bSN)) {
			if (snSeq.getValueAt(0, m_CertSN)) {
				snSeq.getElementAt(1, m_revocationDate);
				bRc = true;
			}
		}

		return bRc;
	}
	catch (...) {
		return false;
	}
}

void CrlRevokedSN::PrintOn(FILE* fp)
{
	try {
		struct tm newtime;
		char b[64];
		time_t t = AsTime_t(m_revocationDate);

		gmtime_s(&newtime, &t);
		asctime_s(b, sizeof(b), &newtime);
		fprintf(fp, "When = %s     SN = ", b);
		LogBinary(fp, (uint8_t*)" ", (uint8_t*)m_CertSN, m_CertSN.Size());
	}
	catch (...) {
		return;
	}
}

//*************************************************
//
//CLASS TBSCertList
//
//*************************************************
TBSCertList::TBSCertList( )
{
}

TBSCertList::TBSCertList(const Buffer& bValue) : TBSCertList()
{
	Initialize(bValue);
}

TBSCertList::~TBSCertList()
{
}

TBSCertList& TBSCertList::operator=(const TBSCertList& original) {
	m_RevokedSerialNumbers = original.m_RevokedSerialNumbers;
	return *this;
}

bool TBSCertList::ParseSNs(const Buffer& bSNs)
{
	try {
		bool   bRc = false;
		SequenceReaderX	snSeq;
		if (snSeq.Initilaize(bSNs)) {
			uint32_t dwIndex = 0;
			Buffer bSN;
			while (snSeq.getElementAt(dwIndex, bSN)) {
				std::shared_ptr<CrlRevokedSN> sn = std::make_shared<CrlRevokedSN>(bSN);
				if (sn) {
					m_RevokedSerialNumbers.push_back(sn);
				}
				dwIndex++;
			}
		}

		return bRc;
	}
	catch (...) {
		return false;
	}
}

bool TBSCertList::Initialize(const Buffer& bValue)
{
	try {
		bool bRc = false;
		uint8_t* pbVal = NULL;
		uint32_t dwValLen = 0;
		SequenceReaderX	seq;
		uint32_t dwValIdx = 0;
		Buffer bElem;

		if (!seq.Initilaize(bValue))
			return false;

		if (seq.getElementAt(5, bElem)) {
			ParseSNs(bElem);
		}

		return bRc;
	}
	catch (...) {
		return false;
	}
}

bool TBSCertList::IsRevoked(Buffer& bSN)
{
	try {
		for (const auto& csn : m_RevokedSerialNumbers) {
			Buffer sn = csn->GetSN();
			if (sn.Size() == bSN.Size()) {
				if (memcmp((void*)sn, (void*)bSN, sn.Size()) == 0) {
					return true;
				}
			}
		}

		return false;
	}
	catch (...) {
		return true;
	}
}

void TBSCertList::RememberRevokedSNs()
{
	try {
		for (const auto& csn : m_RevokedSerialNumbers) {
			Buffer bSN = csn->GetSN();
#ifdef AUTH_SERVICE
			CRLManager::RememberRevokedSN(bSN);
#endif
		}
	}
	catch (...) {
		return;
	}
}

void TBSCertList::PrintOn(FILE* fp)
{
	for (const auto& csn : m_RevokedSerialNumbers) {
		csn->PrintOn(fp);
	}
}

//*************************************************
//
//CLASS CertificateRL
//
//*************************************************
CertificateRL::CertificateRL( )
{
}

CertificateRL::CertificateRL(const Buffer& bValue) : CertificateRL()
{
	Initialize(bValue);
}

CertificateRL::~CertificateRL( )
{
}

CertificateRL& CertificateRL::operator=(const CertificateRL& original) {
	m_TBSCertList = original.m_TBSCertList;
	m_SignatureOID = original.m_SignatureOID;
	m_Signature = original.m_Signature;
	return *this;
}

bool CertificateRL::Initialize(const Buffer& bValue)
{
	try {
		bool			bRc = false;
		SequenceReaderX	seq;

		if (seq.Initilaize(bValue)) {
			if (seq.getElementAt(0, m_TBSbytes)) {
				TBSCertList tbsl(m_TBSbytes);
				m_TBSCertList = tbsl;
				if (seq.getElementAt(1, m_SignatureOID)) {
					if (seq.getValueAt(2, m_Signature)) {
						bRc = true;
					}
				}
			}
		}

		return bRc;
	}
	catch (...) {
		return false;
	}
}

bool CertificateRL::IsRevoked(Buffer& bSN)
{
	std::unique_lock<std::mutex> mlock(m_Mutex);
	return m_TBSCertList.IsRevoked(bSN);
}

bool CertificateRL::IsVerified()
{
	try {
		bool bVerified = false;
		Buffer bHash;
		Buffer bCAfile;
		Buffer bTmp;
		NdacServerConfig& scfg = NdacServerConfig::GetInstance();
		if (memcmp(RSASigSHA256AlgOID, (void*)m_SignatureOID, m_SignatureOID.Size()) == 0) {
			Sha256((uint8_t*)m_TBSbytes, m_TBSbytes.Size(), bHash);
		}
		else if (memcmp(RSASigSHA384AlgOID, (void*)m_SignatureOID, m_SignatureOID.Size()) == 0) {
			Sha384((uint8_t*)m_TBSbytes, m_TBSbytes.Size(), bHash);
		}
		else if (memcmp(RSASigSHA512AlgOID, (void*)m_SignatureOID, m_SignatureOID.Size()) == 0) {
			Sha512((uint8_t*)m_TBSbytes, m_TBSbytes.Size(), bHash);
		}
		else {
			return false;
		}

		{
			uint8_t* pcTmp = (uint8_t*)m_Signature;
			uint32_t sz = m_Signature.Size();
			if ((sz > 1) && (pcTmp[0] == 0x00)) {//ASN BIT STRINGS(0x03) MUST CARRY An UNUSED BITS BYTE. THIS MUST BE ZERO FOR RSA VALUES
				pcTmp++;
				sz--;
			}
			bCAfile = scfg.GetValue(TRUSTED_CA_FILE);
			bVerified = TLSContext::VerifySignatureWithCA((char*)bCAfile, (uint8_t*)bHash, bHash.Size(), pcTmp, sz);
		}

		return bVerified;
	}
	catch (...) {
		return false;
	}
}

void CertificateRL::PrintOn(FILE* fp)
{
	m_TBSCertList.PrintOn(fp);
	LogBinary(fp, (uint8_t*)"sig OID:", (uint8_t*)m_SignatureOID, m_SignatureOID.Size());
	LogBinary(fp, (uint8_t*)"sig:", (uint8_t*)m_Signature, m_Signature.Size());
}

