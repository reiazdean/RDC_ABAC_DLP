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
#include "x509class.h"

using namespace ReiazDean;

/*
Consult https://tools.ietf.org/html/rfc5280
For details
*/

#define		MAX_EXTENSIONS		20
#define		NUM_SAN_NAMES		9

const uint8_t SubjAltNameOID[5] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
const uint8_t UPNOid[12] = { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };
const uint8_t CRLDistPointOID[5] = { 0x06, 0x03, 0x55, 0x1d, 0x1f };
const uint8_t AIADistPointOID[10] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
const uint8_t AIAGeneralName[10] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02 };

char SANChoiceNames[NUM_SAN_NAMES][32] =
{ "otherName", "rfc822Name", "dNSName", "x400Address", "directoryName",
  "ediPartyName", "uniformResourceIdentifier", "iPAddress", "registeredID" };

//*************************************************
//
//CLASS x509AlternateName
//
//*************************************************
x509AlternateName::x509AlternateName()
{
    m_choice = 0;
    m_tag = 0;
}

x509AlternateName::x509AlternateName(const Buffer& bValue) : x509AlternateName()
{
    Buffer bTemp = bValue;
    Initialize(bTemp);
}

x509AlternateName::x509AlternateName(const x509AlternateName& original) : x509AlternateName()
{
    m_asnOID = original.m_asnOID;
    m_asnObject = original.m_asnObject;
    m_choice = original.m_choice;
    m_tag = original.m_tag;
}

x509AlternateName::~x509AlternateName()
{
}

x509AlternateName& x509AlternateName::operator=(const x509AlternateName& original) {
    m_asnOID = original.m_asnOID;
    m_asnObject = original.m_asnObject;
    m_choice = original.m_choice;
    m_tag = original.m_tag;
    return *this;
}

bool x509AlternateName::Parse(Buffer& bValue)
{
    try {
        bool			bRc = false;
        SequenceReaderX	seq;
        Buffer          bTemp = bValue;

        bTemp[0] = CONSTRUCTED_SEQUENCE;
        if (seq.Initilaize(bTemp)) {
            if (seq.getElementAt(0, m_asnOID)) {
                if (seq.getElementAt(1, m_asnObject)) {
                    if (SequenceReaderX::RemoveTL(m_asnObject)) {
                        if (SequenceReaderX::RemoveTL(m_asnObject)) {
                            bRc = true;
                        }
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

bool x509AlternateName::Initialize(Buffer& bSAN)
{
    try {
        bool  bRc = false;
        SequenceReaderX	seq;
        Buffer bTemp = bSAN;

        bTemp[0] = CONSTRUCTED_SEQUENCE;
        if (seq.Initilaize(bTemp)) {
            Buffer bValue;
            if (seq.getElementAt(0, bValue)) {
                SequenceReaderX	seq2;
                if (seq2.Initilaize(bValue)) {
                    if (seq2.getElementAt(0, bValue)) {
                        m_tag = bValue[0];
                        m_choice = m_tag & 0x0f;
                        return Parse(bValue);
                    }
                }
            }
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

void x509AlternateName::PrintSAN(FILE* fp)
{
    fprintf(fp, "%s = %s\n", SANChoiceNames[m_choice], (char*)m_asnObject);
}

//*************************************************
//
//CLASS x509CRLDistributionPoint
//
//*************************************************
x509CRLDistributionPoint::x509CRLDistributionPoint()
{
}

x509CRLDistributionPoint::x509CRLDistributionPoint(const Buffer& bCDP) : x509CRLDistributionPoint()
{
    ParseCDP(bCDP);
}

x509CRLDistributionPoint::x509CRLDistributionPoint(const x509CRLDistributionPoint& original) : x509CRLDistributionPoint()
{
    m_CRLDistPointNames = original.m_CRLDistPointNames;
}

x509CRLDistributionPoint::~x509CRLDistributionPoint()
{
}

x509CRLDistributionPoint& x509CRLDistributionPoint::operator=(const x509CRLDistributionPoint& original) {
    m_CRLDistPointNames = original.m_CRLDistPointNames;
    return *this;
}

/*
* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
*/
bool x509CRLDistributionPoint::IsStringChoice(const Buffer& bCDP)
{
    try {
        uint8_t choice = 6;//the index of the optional type
        Buffer bTmp = bCDP;
        if ((uint8_t)bTmp[0] == (CONTEXT_CLASS + choice)) {
            return true;
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool x509CRLDistributionPoint::IsGeneralName(const Buffer& bCDP)
{
    try {
        uint8_t fullName = 0;//the index of the optional type
        Buffer bTmp = bCDP;
        if ((uint8_t)bTmp[0] == (CONTEXT_CLASS + CONSTRUCTED_TYPE + fullName)) {
            return true;
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool x509CRLDistributionPoint::IsDistPointName(const Buffer& bCDP)
{
    try {
        uint8_t distributionPoint = 0;//the index of the optional type
        Buffer bTmp = bCDP;
        if ((uint8_t)bTmp[0] == (CONTEXT_CLASS + CONSTRUCTED_TYPE + distributionPoint)) {
            return true;
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool x509CRLDistributionPoint::HasReasonCode(const Buffer& bCDP)
{
    try {
        Buffer bTmp = bCDP;
        if ((uint8_t)bTmp[0] == CONSTRUCTED_SEQUENCE) {
            return true;
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool x509CRLDistributionPoint::ParseCDP(const Buffer& bCDP)
{
    try {
        bool   bRc = false;
        SequenceReaderX	cdbSeq;
        if (cdbSeq.Initilaize(bCDP)) {
            uint32_t dwIndex = 0;
            Buffer bCDPname;
            while (cdbSeq.getElementAt(dwIndex, bCDPname)) {
                if (!HasReasonCode(bCDPname)) {//won't process a CDP with a reason code for now
                    if (IsDistPointName(bCDPname) && SequenceReaderX::RemoveTL(bCDPname)) {//won't process a CDP with cRLIssuer for now
                        if (IsGeneralName(bCDPname) && SequenceReaderX::RemoveTL(bCDPname)) {//won't process a CDP with a relative name for now
                            if (IsStringChoice(bCDPname) && SequenceReaderX::RemoveTL(bCDPname)) {
                                m_CRLDistPointNames.push_back(bCDPname);
                                //MessageBoxA(NULL, (char*)bCDPname, "cdpName", MB_OK);
                            }
                        }
                    }
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

bool x509CRLDistributionPoint::GetLdapName(Buffer& bOut)
{
    try {
        for (int i = 0; i < m_CRLDistPointNames.size(); i++)
        {
            if (strncmp(m_CRLDistPointNames[i], "ldap:", 5) == 0) {
                bOut = m_CRLDistPointNames[i];
                return true;
            }
        }

        return false;
    }
    catch (...) {
        bOut.Clear();
        return false;
    }
}

//*************************************************
//
//CLASS x509AIADistributionPoint
//
//*************************************************
x509AIADistributionPoint::x509AIADistributionPoint()
{
}

x509AIADistributionPoint::x509AIADistributionPoint(const Buffer& bAIA) : x509AIADistributionPoint()
{
    ParseAIA(bAIA);
}

x509AIADistributionPoint::x509AIADistributionPoint(const x509AIADistributionPoint& original) : x509AIADistributionPoint()
{
    m_AIADistPointNames = original.m_AIADistPointNames;
}

x509AIADistributionPoint::~x509AIADistributionPoint()
{
}

x509AIADistributionPoint& x509AIADistributionPoint::operator=(const x509AIADistributionPoint& original) {
    m_AIADistPointNames = original.m_AIADistPointNames;
    return *this;
}

bool x509AIADistributionPoint::ParseAIA(const Buffer& bAIA)
{
    try {
        bool   bRc = false;
        SequenceReaderX	aiaSeq;
        if (aiaSeq.Initilaize(bAIA)) {
            uint32_t dwIndex = 0;
            Buffer oid;
            while (aiaSeq.getElementAt(dwIndex, oid)) {//AIAGeneralName
                if (oid.Equals((void*)AIAGeneralName, sizeof(AIAGeneralName))) {
                    Buffer location;
                    dwIndex++;
                    aiaSeq.getElementAt(dwIndex, location);
                    if (SequenceReaderX::RemoveTL(location)) {
                        m_AIADistPointNames.push_back(location);
                    }
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

bool x509AIADistributionPoint::GetLdapName(Buffer& bOut)
{
    try {
        for (int i = 0; i < m_AIADistPointNames.size(); i++)
        {
            if (strncmp(m_AIADistPointNames[i], "ldap:", 5) == 0) {
                bOut = m_AIADistPointNames[i];
                return true;
            }
        }

        return false;
    }
    catch (...) {
        bOut.Clear();
        return false;
    }
}

//*************************************************
//
//CLASS TBSCertificate
//
//*************************************************
TBSCertificate::TBSCertificate()
{
    m_IsOkay = false;
    m_SubjectAlternateNames.reserve(MAX_EXTENSIONS);
}

TBSCertificate::TBSCertificate(const Buffer& bValue) : TBSCertificate()
{
    m_IsOkay = Initialize(bValue);
}

TBSCertificate::~TBSCertificate()
{
}

TBSCertificate& TBSCertificate::operator=(const TBSCertificate& original) {
    m_IsOkay = original.m_IsOkay;
    m_version = original.m_version;
    m_serialNum = original.m_serialNum;
    m_SignatureOID = original.m_SignatureOID;
    m_Issuer = original.m_Issuer;
    m_Validity = original.m_Validity;
    m_notBefore = original.m_notBefore;
    m_notAfter = original.m_notAfter;
    m_Subject = original.m_Subject;
    m_PublicKeyInfo = original.m_PublicKeyInfo;
    m_IssuerUID = original.m_IssuerUID;
    m_SubjectUID = original.m_SubjectUID;
    m_SubjectAlternateNames = original.m_SubjectAlternateNames;
    m_CRLDistPoints = original.m_CRLDistPoints;
    m_AIADistPoints = original.m_AIADistPoints;
    return *this;
}

bool TBSCertificate::GetUPNSubjectAltName(Buffer& bOut)
{
    try {
        for (int i = 0; i < m_SubjectAlternateNames.size(); i++)
        {
            Buffer oid = m_SubjectAlternateNames[i]->GetOID();
            if (memcmp((uint8_t*)oid, UPNOid, sizeof(UPNOid)) == 0) {
                bOut = m_SubjectAlternateNames[i]->GetAsnObject();
                return true;
            }
        }

        return false;
    }
    catch (...) {
        bOut.Clear();
        return false;
    }
}

void TBSCertificate::PrintSANs(FILE* fp)
{
    for (int i = 0; i < m_SubjectAlternateNames.size(); i++)
    {
        m_SubjectAlternateNames[i]->PrintSAN(fp);
    }
}

bool TBSCertificate::GetLdapCDP(Buffer& bOut)
{
    try {
        for (int i = 0; i < m_CRLDistPoints.size(); i++)
        {
            if (m_CRLDistPoints[i]->GetLdapName(bOut)) {
                return true;
            }
        }

        return false;
    }
    catch (...) {
        bOut.Clear();
        return false;
    }
}

bool TBSCertificate::GetLdapAIA(Buffer& bOut)
{
    try {
        for (int i = 0; i < m_AIADistPoints.size(); i++)
        {
            if (m_AIADistPoints[i]->GetLdapName(bOut)) {
                return true;
            }
        }

        return false;
    }
    catch (...) {
        bOut.Clear();
        return false;
    }
}

bool TBSCertificate::ParseCDPs(const Buffer& bCDPs)
{
    try {
        bool   bRc = false;
        SequenceReaderX	cdbSeq;
        if (cdbSeq.Initilaize(bCDPs)) {
            uint32_t dwIndex = 0;
            Buffer bCDP;
            while (cdbSeq.getElementAt(dwIndex, bCDP)) {
                std::shared_ptr<x509CRLDistributionPoint> x = std::make_shared<x509CRLDistributionPoint>(bCDP);
                if (x) {
                    m_CRLDistPoints.push_back(x);
                }
                dwIndex++;
            }
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool TBSCertificate::ParseAIA(const Buffer& bAIAs)
{
    try {
        bool   bRc = false;
        SequenceReaderX	aiaSeq;
        if (aiaSeq.Initilaize(bAIAs)) {
            uint32_t dwIndex = 0;
            Buffer bAIA;
            while (aiaSeq.getElementAt(dwIndex, bAIA)) {
                std::shared_ptr<x509AIADistributionPoint> x = std::make_shared<x509AIADistributionPoint>(bAIA);
                if (x) {
                    m_AIADistPoints.push_back(x);
                }
                dwIndex++;
            }
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool TBSCertificate::ReadOptionals(SequenceReaderX& seq)
{
    /*
    The first 7 elements are mandatory elements and next there could be 3 optional elements
    RFC5280 claims that CAs are NOT supposed to add the IssuerUID or the SubjetcUID, but applications must check
    Extensions may be the 3rd optional.
    SANs could be the 8th, 9th or 10th element
    */
    try {
        bool   bRc = false;
        Buffer bExtensions;
        SequenceReaderX	exSeq;
        bool bFound = seq.getValueAt(9, bExtensions) || seq.getValueAt(8, bExtensions) || seq.getValueAt(7, bExtensions);

        if (!bFound) {
            return false;
        }

        if (exSeq.Initilaize(bExtensions)) {
            uint32_t dwIndex = 0;
            Buffer bExt;
            while (exSeq.getElementAt(dwIndex, bExt)) {
                SequenceReaderX sExt;
                if (sExt.Initilaize(bExt)) {
                    Buffer oid;
                    sExt.getElementAt(0, oid);
                    if (oid.Equals((void*)SubjAltNameOID, sizeof(SubjAltNameOID))) {
                        Buffer val;
                        if (sExt.getElementAt(1, val)) {
                            std::shared_ptr<x509AlternateName> x = std::make_shared<x509AlternateName>(val);
                            if (x) {
                                m_SubjectAlternateNames.push_back(x);
                            }
                        }
                    }
                    else if (oid.Equals((void*)CRLDistPointOID, sizeof(CRLDistPointOID))) {
                        Buffer bCDPs;
                        if (sExt.getElementAt(1, bCDPs)) {
                            if (SequenceReaderX::RemoveTL(bCDPs)) {
                                ParseCDPs(bCDPs);
                            }
                        }
                    }
                    else if (oid.Equals((void*)AIADistPointOID, sizeof(AIADistPointOID))) {
                        Buffer bAIA;
                        if (sExt.getElementAt(1, bAIA)) {
                            if (SequenceReaderX::RemoveTL(bAIA)) {
                                ParseAIA(bAIA);
                            }
                        }
                    }
                }
                dwIndex++;
            }
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool TBSCertificate::Initialize(const Buffer& bValue)
{
    try {
        uint8_t         defaultVer[3] = { 0x02, 0x01, 0x00 };
        uint8_t* pbVal = NULL;
        uint32_t			dwValLen = 0;
        SequenceReaderX	seq;
        uint32_t			dwValIdx = 0;

        if (!seq.Initilaize(bValue))
            return false;

        if (!seq.getValueAt(dwValIdx++, m_version)) {
            return false;
        }
        if (!seq.getValueAt(dwValIdx++, m_serialNum)) {
            return false;
        }
        if (!seq.getValueAt(dwValIdx++, m_SignatureOID)) {
            return false;
        }
        if (!seq.getValueAt(dwValIdx++, m_Issuer)) {
            return false;
        }

        if (!seq.getElementAt(dwValIdx++, m_Validity)) {
            return false;
        }
        else {
            SequenceReaderX	seq2;
            if (!seq2.Initilaize(m_Validity)) {
                return false;
            }
            else {
                if (!seq2.getElementAt(0, m_notBefore)) {
                    return false;
                }
                if (!seq2.getElementAt(1, m_notAfter)) {
                    return false;
                }
            }
        }

        if (!seq.getValueAt(dwValIdx++, m_Subject)) {
            return false;
        }
        if (!seq.getElementAt(dwValIdx++, m_PublicKeyInfo)) {
            return false;
        }
        
        return ReadOptionals(seq);;
    }
    catch (...) {
        return false;
    }
}

bool TBSCertificate::IsValid()
{
    try {
        time_t			 start;
        time_t			 end;
        time_t			 now;

        start = AsTime_t(m_notBefore);
        if (start == 0) {
            return false;
        }
        /* {
            struct tm newtime;
            char b[64];
            gmtime_s(&newtime, &start);
            asctime_s(b, sizeof(b), &newtime);
            fprintf(stdout, "Start = %s\n", b);
        }*/
        end = AsTime_t(m_notAfter);
        if (end == 0) {
            return false;
        }
        /* {
            struct tm newtime;
            char b[64];
            gmtime_s(&newtime, &end);
            asctime_s(b, sizeof(b), &newtime);
            fprintf(stdout, "End = %s\n", b);
        }*/
        time(&now);

        //double difftime (time_t end, time_t beginning);
        return ((difftime(now, start) > 0.0f) && (difftime(end, now) > 0.0f));
    }
    catch (...) {
        return false;
    }
}

void TBSCertificate::PrintOn(FILE* fp)
{
    LogBinary(fp, (uint8_t*)"ver:", (uint8_t*)m_version, m_version.Size());
    LogBinary(fp, (uint8_t*)"SN: ", (uint8_t*)m_serialNum, m_serialNum.Size());
    LogBinary(fp, (uint8_t*)"OID:", (uint8_t*)m_SignatureOID, m_SignatureOID.Size());
    LogBinary(fp, (uint8_t*)"Iss: ", (uint8_t*)m_Issuer, m_Issuer.Size());
    LogBinary(fp, (uint8_t*)"End:", (uint8_t*)m_notAfter, m_notAfter.Size());
    LogBinary(fp, (uint8_t*)"Subj: ", (uint8_t*)m_Subject, m_Subject.Size());
    LogBinary(fp, (uint8_t*)"PK:", (uint8_t*)m_PublicKeyInfo, m_PublicKeyInfo.Size());

}

//*************************************************
//
//CLASS Certificate
//
//*************************************************
Certificate::Certificate()
{
    m_Valid = false;
}

Certificate::Certificate(const Buffer& bValue) : Certificate()
{
    m_Valid = Initialize(bValue);
    m_Value = bValue;
}

Certificate::~Certificate()
{
}

Certificate& Certificate::operator=(const Certificate& original) {
    m_TBSCertificate = original.m_TBSCertificate;
    m_SignatureOID = original.m_SignatureOID;
    m_Signature = original.m_Signature;
    m_Value = original.m_Value;
    return *this;
}

bool Certificate::Initialize(const Buffer& bValue)
{
    try {
        bool			bRc = false;
        SequenceReaderX	seq;

        if (seq.Initilaize(bValue)) {
            Buffer b;
            if (seq.getElementAt(0, b)) {
                TBSCertificate tbs(b);
                m_TBSCertificate = tbs;
                if (seq.getValueAt(1, m_SignatureOID)) {
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

bool Certificate::GetUPNSubjectAltName(Buffer& bOut)
{
    return m_TBSCertificate.GetUPNSubjectAltName(bOut);
}

void Certificate::PrintSANs(FILE* fp)
{
    m_TBSCertificate.PrintSANs(fp);
}

bool Certificate::IsValid()
{
    if (!IsOkay()) {
        return false;
    }
    return m_TBSCertificate.IsValid();
}

bool Certificate::GetPublicKeyInfo(Buffer& bOut)
{
    if (!IsOkay()) {
        return false;
    }
    bOut = m_TBSCertificate.GetPublicKeyInfo();
    return true;
}

bool Certificate::GetSubject(Buffer& bOut)
{
    if (!IsOkay()) {
        return false;
    }
    bOut = m_TBSCertificate.GetSubject();
    return true;
}

bool Certificate::GetSerialNumber(Buffer& bOut)
{
    if (!IsOkay()) {
        return false;
    }
    bOut = m_TBSCertificate.GetSerialNumber();
    return true;
}

bool Certificate::GetIssuer(Buffer& bOut)
{
    if (!IsOkay()) {
        return false;
    }
    bOut = m_TBSCertificate.GetIssuer();
    return true;
}

bool Certificate::GetStart(Buffer& bOut)
{
    if (!IsOkay()) {
        return false;
    }
    bOut = m_TBSCertificate.GetStart();
    return true;
}

bool Certificate::GetEnd(Buffer& bOut)
{
    if (!IsOkay()) {
        return false;
    }
    bOut = m_TBSCertificate.GetEnd();
    return true;
}

bool Certificate::GetCRLDistPoints(std::vector<std::shared_ptr<x509CRLDistributionPoint>>& cdp)
{
    if (!IsOkay()) {
        return false;
    }
    cdp = m_TBSCertificate.GetCRLDistPoints();
    return true;
}
