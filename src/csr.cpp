/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SequenceReader.h"
#include "NdacConfig.h"

#define					MAX_SUBJ_SZ			256
#define					OID_BASE			128
#define					OID_MAX				120

void DecodePEM( unsigned char* pcPem, unsigned char* pcData, unsigned int* pdwLen, unsigned int iSize );
extern Buffer* pPasswordBuffer;

const unsigned char codeTable[65] =
{'A','B','C','D','E','F','G','H','I','J','K','L','M',
 'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
 'a','b','c','d','e','f','g','h','i','j','k','l','m',
 'n','o','p','q','r','s','t','u','v','w','x','y','z',
 '0','1','2','3','4','5','6','7','8','9','+','/','='};

HCRYPTPROV	hCryptProv = NULL;
HCRYPTKEY	hUserKey = 0;

//http://msdn.microsoft.com/en-us/library/windows/desktop/aa381133(v=vs.85).aspx
//http://msdn.microsoft.com/en-us/library/windows/desktop/aa379076(v=vs.85).aspx
const BYTE SubjCntryOID[5]					= {0x06, 0x03, 0x55, 0x04, 0x06};
const BYTE SubjStateOID[5]					= {0x06, 0x03, 0x55, 0x04, 0x08};
const BYTE SubjCityOID[5]					= {0x06, 0x03, 0x55, 0x04, 0x07};
const BYTE SubjOrgOID[5]					= {0x06, 0x03, 0x55, 0x04, 0x0a};
const BYTE SubjUnitOID[5]					= {0x06, 0x03, 0x55, 0x04, 0x0b};
const BYTE SubjUserOID[5]					= {0x06, 0x03, 0x55, 0x04, 0x03};
const BYTE SubjAltNameOID[5]				= {0x06, 0x03, 0x55, 0x1d, 0x11};
const BYTE UPNOid[12]						= {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03};
const BYTE SubjEmailOID[11]					= {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};

const BYTE RSAPublicKeyOID[15]				= {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};//a sequence of an OID(06) and NULL(05)
const BYTE RSASigAlgOID[15]					= {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};//a sequence of an OID(06) and NULL(05)
//const BYTE RSASigSHA256AlgOID[15]			= {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};//a sequence of an OID(06) and NULL(05)
//certificate template OID = 1.3.6.1.4.1.311.21.7.
const BYTE AttributePwdOID[11]				= {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07};

const BYTE ExtensionsOID[11]				= {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e};
const BYTE CertificateTemplateOID[11]		= {0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02};

const BYTE SmartCardUserDER[30]				= {0x04, 0x1c, 0x1e, 0x1a, 0x00, 0x53, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x63, 
                                               0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72};

const BYTE SmartCardLogonDER[32]			= {0x04, 0x1e, 0x1e, 0x1c, 0x00, 0x53, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x63, 
                                               0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00, 0x4c, 0x00, 0x6f, 0x00, 0x67, 0x00, 0x6f, 0x00, 0x6e};

const BYTE SmartCardLogon2DER[34]			= {0x04, 0x20, 0x1e, 0x1e, 0x00, 0x53, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x63, 
                                               0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00, 0x4c, 0x00, 0x6f, 0x00, 0x67, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x32};


const BYTE SmartCardUser[43]				= {0x30, 0x29, 
				                                     0x06, 0x09,
                                                           0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02,
                                                     0x04, 0x1c,
                                                           0x1e, 0x1a,
                                                                 0x00, 0x53, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74,//Smart
				                                                 0x00, 0x63, 0x00, 0x61, 0x00, 0x72, 0x00, 0x64,//card
																 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72};//User

const BYTE SmartCardLogon[45]				= {0x30, 0x2b, 
				                                     0x06, 0x09,
                                                           0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02,
                                                     0x04, 0x1e,
                                                           0x1e, 0x1c,
                                                                 0x00, 0x53, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74,//Smart
				                                                 0x00, 0x63, 0x00, 0x61, 0x00, 0x72, 0x00, 0x64,//card
																 0x00, 0x4c, 0x00, 0x6f, 0x00, 0x67, 0x00, 0x6f, 0x00, 0x6e};//Logon

const BYTE	ClientKeyUsage[16]				= {0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0};

const BYTE	ServerKeyUsage[21]              = { 0x30, 0x13, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };

const BYTE DNSOid[3]                        = {0x55, 0x04, 0x64};

/*
30 29  
     06 03 55 1d 25						   	                   2.5.29.37 Enhanced Key Usage
     04 22 
           30 20 
              06 0a 2b 06 01 04 01 82 37 0a  03 04				1.3.6.1.4.1.311.10.3.4 Encrypting File System
              06 08 2b 06 01 05 05 07 03 04 					1.3.6.1.5.5.7.3.4 Secure Email
              06 08 2b 06 01 05 05 07 03 02                     1.3.6.1.5.5.7.3.2 Client Authentication
*/
const BYTE EnhancedKeyUsage[31]				= { 0x30, 0x1d,
	                                                  0x06, 0x03, 0x55, 0x1d, 0x25,
													  0x04, 0x16,
													        0x30, 0x14,
													              0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04,
													              0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
                                               };

const BYTE ServerEnhancedKeyUsage[31] = { 0x30, 0x13,
													  0x06, 0x03, 0x55, 0x1d, 0x25,
													  0x04, 0x0c,
															0x30, 0x0a,
																  0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01
};

extern Buffer SubjCntry;
extern Buffer SubjState;
extern Buffer SubjCity;
extern Buffer SubjOrg;
extern Buffer SubjUnit;
extern Buffer SubjUser;
extern Buffer SubjAltName;
extern Buffer SubjEmail;
extern Buffer Password;
extern Buffer Extensions;
extern Buffer Signature;
BYTE OID_Bytes[OID_BASE];

void Message(LPWSTR szPrefix, HRESULT hr)
{
    LPWSTR   szMessage;

    if (hr == S_OK)
        {
        wprintf(szPrefix);
        return;
        }
 
    if (HRESULT_FACILITY(hr) == FACILITY_WINDOWS)
        hr = HRESULT_CODE(hr);
 
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        hr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
        (LPWSTR)&szMessage,
        0,
        NULL);

  //  wprintf(L"%s: %s(%lx)\n", szPrefix, szMessage, hr);
	MessageBoxW(NULL, szMessage, szPrefix, MB_OK );
    
    LocalFree(szMessage);
}  // Messag

//Encode binary data to PEM format
BOOL
base64Encode(
	uint8_t* pbDataIn,
	size_t dwLenIn,
	Buffer& bPEM)
{
	try {
		BOOL bRc = false;
		size_t i;
		uint8_t in[3];
		uint8_t out[5];//3 is expanded to 4, but we will have a NULL terminator for strcat
		size_t dwData;
		size_t szPem = 0;

		bPEM.Clear();
		//PEM data is expanded by 4/3 
		szPem = dwLenIn / 3;
		if ((szPem * 3) != dwLenIn) {
			szPem += 1;
		}
		szPem *= 4;
		//every 64 unsigned chars of PEM data will end with a cr, 0x0A, so calculate how many we need
		//and adjust the size
		dwData = szPem / 64;
		if ((dwData * 64) != szPem) {
			dwData += 1;
		}
		szPem += dwData;
		szPem += 128;//over allocate jic

		if (!pbDataIn) {
			return bRc;
		}
		else {
			Buffer bTmp(szPem);

			memset(out, 0, 5);
			for (i = 0; i < dwLenIn; i += 3)
			{
				if (i && (i % 48) == 0) {
					bTmp.EOLN();
				}

				memset(in, 0, 3);
				memset(out, '=', 4);
				if ((dwLenIn - i) < 2)
				{
					unsigned char b;
					memcpy(in, pbDataIn + i, 1);
					out[0] = codeTable[in[0] >> 2];
					b = (in[0] << 6) | 0;
					out[1] = codeTable[b >> 2];
				}
				else if ((dwLenIn - i) < 3)
				{
					unsigned char b;
					memcpy(in, pbDataIn + i, 2);
					out[0] = codeTable[in[0] >> 2];
					b = (in[0] << 6) | (in[1] >> 2);
					out[1] = codeTable[b >> 2];
					b = (in[1] << 4) | 0;
					out[2] = codeTable[b >> 2];
				}
				else
				{
					unsigned char b;
					memcpy(in, pbDataIn + i, 3);
					out[0] = codeTable[in[0] >> 2];
					b = (in[0] << 6) | (in[1] >> 2);
					out[1] = codeTable[b >> 2];
					b = (in[1] << 4) | (in[2] >> 4);
					out[2] = codeTable[b >> 2];
					out[3] = codeTable[in[2] & 0x3F];
				}

				bTmp.Append((void*)out, strlen((char*)out));
			}
			bTmp.EOLN();
			bPEM.Append(bTmp);
			bRc = true;
		}

		return bRc;
	}
	catch (...) {
		bPEM.Clear();
		return false;
	}
}

bool HashAndSign(Buffer& bData, Buffer& bSignature, ALG_ID algid )
{
#ifdef AUTH_SERVICE
	return false;
#else
	NdacClientConfig& cfg = NdacClientConfig::GetInstance();
	try {
		Buffer bKSP_w = cfg.GetValueW(KEY_STORAGE_PROVIDER);

		KSPkey ksp((WCHAR*)bKSP_w);
		if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)MY_SMARTCARD_CONTAINER, 0)) {
			Buffer bHash;
			switch (algid) {
			case CALG_SHA1:
				return false;
				break;
			case CALG_SHA_384:
				Sha384((uint8_t*)bData, bData.Size(), bHash);
				break;
			case CALG_SHA_512:
				Sha512((uint8_t*)bData, bData.Size(), bHash);
				break;
			default:
				Sha256((uint8_t*)bData, bData.Size(), bHash);
				break;
			}
			
			if (ERROR_SUCCESS == ksp.SignHash((uint8_t*)bHash, bHash.Size(), bSignature)) {
				return true;
			}
		}
	}
	catch (...) {
		bSignature.Clear();
		return false;
	}

	return false;
#endif
}

BOOL
BuildUserCSR(
	Buffer& bPkModulus,
	Buffer& bPkExp,
	char* pcTemplate,
	ALG_ID algid,
	Buffer& bCSR)
{
	BOOL bRC = false;
	Buffer seqCSR;
	Buffer seqInfo;
	Buffer seqSubj;
	Buffer seqPubKey;
	Buffer seqSig;
	Buffer seqDN;
	Buffer seqModExp;
	Buffer seqSANs;
	Buffer seqExtensions;
	Buffer bSignature;
	BYTE bVersion[3] = {0x02, 0x01, 0x00};

	try {
		//add the version to the info
		seqInfo.Append((void*)bVersion, sizeof(bVersion));

		SubjCntry.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjCntryOID, sizeof(SubjCntryOID));
		seqDN.Append(SubjCntry);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjState.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjStateOID, sizeof(SubjStateOID));
		seqDN.Append(SubjState);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjCity.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjCityOID, sizeof(SubjCityOID));
		seqDN.Append(SubjCity);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjOrg.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjOrgOID, sizeof(SubjOrgOID));
		seqDN.Append(SubjOrg);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjUnit.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjUnitOID, sizeof(SubjUnitOID));
		seqDN.Append(SubjUnit);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjUser.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjUserOID, sizeof(SubjUserOID));
		seqDN.Append(SubjUser);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjEmail.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjEmailOID, sizeof(SubjEmailOID));
		seqDN.Append(SubjEmail);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		seqSubj.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqInfo.Append(seqSubj);

		seqModExp.Append(bPkModulus);
		seqModExp.Append(bPkExp);
		seqModExp.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqModExp.Prepend((void*)"\0", 1);
		seqModExp.ASN1Wrap(UNIVERSAL_TYPE_BITSTR);

		seqPubKey.Append((void*)RSAPublicKeyOID, sizeof(RSAPublicKeyOID));
		seqPubKey.Append(seqModExp);
		seqPubKey.ASN1Wrap(CONSTRUCTED_SEQUENCE);

		seqInfo.Append(seqPubKey);

		//add the subject alt name
		//http://www.ietf.org/rfc/rfc3280.txt page 33
		SubjAltName.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		SubjAltName.ASN1Wrap(0xA0);
		SubjAltName.Prepend((void*)UPNOid, sizeof(UPNOid));
		SubjAltName.ASN1Wrap(0xA0);
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
		SubjAltName.Prepend((void*)SubjAltNameOID, sizeof(SubjAltNameOID));
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.Prepend((void*)ClientKeyUsage, sizeof(ClientKeyUsage));
		if (strcmp("SmartcardUser", pcTemplate) == 0) {
			SubjAltName.Prepend((void*)SmartCardUser, sizeof(SmartCardUser));
		}
		else {
			SubjAltName.Prepend((void*)SmartCardLogon, sizeof(SmartCardLogon));
		}
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.ASN1Wrap(CONSTRUCTED_SET);
		SubjAltName.Prepend((void*)ExtensionsOID, sizeof(ExtensionsOID));
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.ASN1Wrap(0xA0);

		seqInfo.Append(SubjAltName);
		seqInfo.ASN1Wrap(CONSTRUCTED_SEQUENCE);

		seqCSR.Append(seqInfo);

		if (HashAndSign(seqInfo, bSignature, algid) == false) {
			return false;
		}
		bSignature.Prepend((void*)"\0", 1);
		bSignature.ASN1Wrap(UNIVERSAL_TYPE_BITSTR);

		if (algid == CALG_SHA1) {
			seqCSR.Append((void*)RSASigAlgOID, sizeof(RSASigAlgOID));
		}
		else {
			seqCSR.Append((void*)RSASigSHA256AlgOID, sizeof(RSASigSHA256AlgOID));
		}

		seqCSR.Append(bSignature);
		seqCSR.ASN1Wrap(CONSTRUCTED_SEQUENCE);

		bCSR.Clear();
		/* {
			bCSR.Append(seqCSR);
			bRC = true;
		}*/
		if (base64Encode((uint8_t*)seqCSR, seqCSR.Size(), bCSR)) {
			bCSR.Prepend((void*)"-----BEGIN CERTIFICATE REQUEST-----\n", strlen("-----BEGIN CERTIFICATE REQUEST-----\n"));
			bCSR.Append((void*)"-----END CERTIFICATE REQUEST-----\n", strlen("-----END CERTIFICATE REQUEST-----\n"));
			bCSR.NullTerminate();
			bRC = true;
		}

	}
	catch (...) {
		bCSR.Clear();
		return false;
	}

	return bRC;

}

bool
createOrOpenUserKey(
	Buffer& bPublicKey
)
{
#ifdef AUTH_SERVICE
	return false;
#else
	NdacClientConfig& cfg = NdacClientConfig::GetInstance();
	try {
		SECURITY_STATUS ss = NTE_FAIL;
		Buffer bKSP_w = cfg.GetValueW(KEY_STORAGE_PROVIDER);

		KSPkey ksp((WCHAR*)bKSP_w);
		ss = ksp.OpenKey((WCHAR*)MY_SMARTCARD_CONTAINER, 0);
		if (ss != ERROR_SUCCESS)  {
			ss = ksp.CreateKey((WCHAR*)MY_SMARTCARD_CONTAINER, NCRYPT_ALLOW_DECRYPT_FLAG);
		}
		
		if (ss == ERROR_SUCCESS) {
			ss = ksp.GetPublicKey(bPublicKey);
		}

		if (ss == ERROR_SUCCESS) {
			BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)(void*)bPublicKey;
			size_t expected = sizeof(BCRYPT_RSAKEY_BLOB) + pBlob->cbModulus + pBlob->cbPublicExp;
			return (expected == bPublicKey.Size());
		}

		return false;
	}
	catch (...) {
		bPublicKey.Clear();
		return false;
	}
#endif
}


/*//CERTSRV_E_UNSUPPORTED_CERT_TYPE Smartcard User
	FUNCTION:		int main(int argc, char* argv[])
	openssl req -text -noout -verify -in mycsr.csr
*/
BOOL
createUserCSR(
	char* subjUser,
	char* subjCntry,
	char* subjState,
	char* subjCity,
	char* subjOrg,
	char* subjUnit,
	char* subjUPN,
	char* subjEmail,
	char* password,
	char* scTemplate,
	ALG_ID algid,
	Buffer& bCSR)
{
	BOOL bRC = FALSE;
	Buffer bPubKey;
	Buffer bModulus;
	Buffer bExp;

	try {
		if (createOrOpenUserKey(bPubKey)) {
			BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)(void*)bPubKey;
			uint8_t* pData = (uint8_t*)bPubKey + sizeof(BCRYPT_RSAKEY_BLOB);

			bExp.Append((void*)pData, pBlob->cbPublicExp);
			bExp.AssertIntegerPositivity();
			bModulus.Append((void*)(pData + pBlob->cbPublicExp), pBlob->cbModulus);
			bModulus.AssertIntegerPositivity();
			bModulus.ASN1Wrap(UNIVERSAL_TYPE_INT);
			bExp.ASN1Wrap(UNIVERSAL_TYPE_INT);
		}
		else {
			return FALSE;
		}

		SubjUser.Clear();
		SubjCntry.Clear();
		SubjState.Clear();
		SubjCity.Clear();
		SubjOrg.Clear();
		SubjUnit.Clear();
		SubjAltName.Clear();
		SubjEmail.Clear();
		Password.Clear();

		SubjUser.Append((void*)subjUser, strlen(subjUser));
		SubjCntry.Append((void*)subjCntry, strlen(subjCntry));
		SubjState.Append((void*)subjState, strlen(subjState));
		SubjCity.Append((void*)subjCity, strlen(subjCity));
		SubjOrg.Append((void*)subjOrg, strlen(subjOrg));
		SubjUnit.Append((void*)subjUnit, strlen(subjUnit));
		SubjAltName.Append((void*)subjUPN, strlen(subjUPN));
		SubjEmail.Append((void*)subjEmail, strlen(subjEmail));
		Password.Append((void*)password, strlen(password));

		bRC = BuildUserCSR(bModulus, bExp, scTemplate, algid, bCSR);
	}
	catch (...) {
		bCSR.Clear();
		return false;
	}

	return bRC;
}

BOOL
OsslHashAndSign(
	Buffer& bData,
	Buffer& bSignature,
	EVP_PKEY* pkey)
{
	EVP_PKEY_CTX* ctx = nullptr;
	BOOL bRet = false;
	Buffer bHash;

	try {
		Sha256((uint8_t*)bData, bData.Size(), bHash);

		ctx = EVP_PKEY_CTX_new(pkey, 0);
		if (ctx) {
			if (EVP_PKEY_sign_init(ctx)) {
				size_t  outlen;

				EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
				EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
				if (EVP_PKEY_sign(ctx, 0, &outlen, (uint8_t*)bHash, bHash.Size())) {
					Buffer b(outlen);
					if (EVP_PKEY_sign(ctx, (uint8_t*)b, &outlen, (uint8_t*)bHash, bHash.Size()))
					{
						bSignature.Append((uint8_t*)b, outlen);
						bRet = TRUE;
					}
				}
			}

			EVP_PKEY_CTX_free(ctx);
		}
	}
	catch (...) {
		if (ctx) {
			EVP_PKEY_CTX_free(ctx);
		}
		bSignature.Clear();
		return FALSE;
	}

	return bRet;
}

BOOL
BuildServerCSR(
	EVP_PKEY* pkey,
	Buffer& bPkModulus,
	Buffer& bPkExp,
	Buffer& bCSR)
{
	BOOL bRC = false;
	Buffer seqCSR;
	Buffer seqInfo;
	Buffer seqSubj;
	Buffer seqPubKey;
	Buffer seqSig;
	Buffer seqDN;
	Buffer seqModExp;
	Buffer seqSANs;
	Buffer seqExtensions;
	Buffer bSignature;
	BYTE bVersion[3] = { 0x02, 0x01, 0x00 };

	try {
		//add the version to the info
		seqInfo.Append((void*)bVersion, sizeof(bVersion));

		SubjCntry.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjCntryOID, sizeof(SubjCntryOID));
		seqDN.Append(SubjCntry);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjState.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjStateOID, sizeof(SubjStateOID));
		seqDN.Append(SubjState);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjCity.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjCityOID, sizeof(SubjCityOID));
		seqDN.Append(SubjCity);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjOrg.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjOrgOID, sizeof(SubjOrgOID));
		seqDN.Append(SubjOrg);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjUnit.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjUnitOID, sizeof(SubjUnitOID));
		seqDN.Append(SubjUnit);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		SubjUser.ASN1Wrap(UNIVERSAL_TYPE_UTF8STRING);
		seqDN.Append((void*)SubjUserOID, sizeof(SubjUserOID));
		seqDN.Append(SubjUser);
		seqDN.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqDN.ASN1Wrap(CONSTRUCTED_SET);
		seqSubj.Append(seqDN);
		seqDN.Clear();

		seqSubj.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqInfo.Append(seqSubj);

		seqModExp.Append(bPkModulus);
		seqModExp.Append(bPkExp);
		seqModExp.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		seqModExp.Prepend((void*)"\0", 1);
		seqModExp.ASN1Wrap(UNIVERSAL_TYPE_BITSTR);

		seqPubKey.Append((void*)RSAPublicKeyOID, sizeof(RSAPublicKeyOID));
		seqPubKey.Append(seqModExp);
		seqPubKey.ASN1Wrap(CONSTRUCTED_SEQUENCE);

		seqInfo.Append(seqPubKey);

		//add the subject alt name
		//http://www.ietf.org/rfc/rfc3280.txt page 33
		SubjAltName.ASN1Wrap(0x82);
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
		SubjAltName.Prepend((void*)SubjAltNameOID, sizeof(SubjAltNameOID));
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.Prepend((void*)ServerKeyUsage, sizeof(ServerKeyUsage));

		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.ASN1Wrap(CONSTRUCTED_SET);
		SubjAltName.Prepend((void*)ExtensionsOID, sizeof(ExtensionsOID));
		SubjAltName.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		SubjAltName.ASN1Wrap(0xA0);

		seqInfo.Append(SubjAltName);
		seqInfo.ASN1Wrap(CONSTRUCTED_SEQUENCE);

		seqCSR.Append(seqInfo);

		if (OsslHashAndSign(seqInfo, bSignature, pkey) == false) {
			return false;
		}
		bSignature.Prepend((void*)"\0", 1);
		bSignature.ASN1Wrap(UNIVERSAL_TYPE_BITSTR);

		seqCSR.Append((void*)RSASigSHA256AlgOID, sizeof(RSASigSHA256AlgOID));

		seqCSR.Append(bSignature);
		seqCSR.ASN1Wrap(CONSTRUCTED_SEQUENCE);

		bCSR.Clear();
		/* {
			bCSR.Append(seqCSR);
			bRC = true;
		}*/
		if (base64Encode((uint8_t*)seqCSR, seqCSR.Size(), bCSR)) {
			bCSR.Prepend((void*)"-----BEGIN CERTIFICATE REQUEST-----\n", strlen("-----BEGIN CERTIFICATE REQUEST-----\n"));
			bCSR.Append((void*)"-----END CERTIFICATE REQUEST-----\n", strlen("-----END CERTIFICATE REQUEST-----\n"));
			bCSR.NullTerminate();
			bRC = TRUE;
		}
	}
	catch (...) {
		bCSR.Clear();
		return FALSE;
	}

	return bRC;

}

BOOL getPublicKey(EVP_PKEY* pkey, Buffer& bExp, Buffer& bMod)
{
	BOOL bRC = FALSE;
	BIGNUM* e = NULL;
	BIGNUM* n = NULL;
	int r = -1;
	uint8_t eC[128];
	uint8_t eN[512];

	try {
		/* get public exponent */
		if (1 == EVP_PKEY_get_bn_param(pkey, "e", &e)) {
			r = BN_bn2bin(e, eC);
			bExp.Append(eC, r);
			BN_free(e);
			if (1 == EVP_PKEY_get_bn_param(pkey, "n", &n)) {
				r = BN_bn2bin(n, eN);
				bMod.Append(eN, r);
				BN_free(n);
				bRC = TRUE;
			}
		}
	}
	catch (...) {
		bExp.Clear();
		bMod.Clear();
		return FALSE;
	}
	
	return bRC;
}


/*//CERTSRV_E_UNSUPPORTED_CERT_TYPE Smartcard User
	FUNCTION:		int main(int argc, char* argv[])
	openssl req -text -noout -verify -in mycsr.csr
*/
BOOL
createServerCSR(
	char* subjUser,
	char* subjCntry,
	char* subjState,
	char* subjCity,
	char* subjOrg,
	char* subjUnit,
	char* subjDNS,
	Buffer& bCSR)
{
	BOOL bRC = FALSE;
	Buffer bServerPK;
#ifdef AUTH_SERVICE
	NdacServerConfig& scfg = NdacServerConfig::GetInstance();
	EVP_PKEY* privkey = nullptr;
	FILE* fp = nullptr;
	Buffer bCertData;
	Buffer bPubKey;
	DWORD dwPubLen = 0;
	Buffer bModulus;
	DWORD dwModLen = 256;
	Buffer bExp;
	DWORD dwExpLen = 4;

	try {
		scfg.GetValue(TLS_PRIV_KEY_FILE, bServerPK);
		fp = f_open_f((char*)bServerPK, (char*)"r");
		if (!fp) {
			return bRC;
		}

		privkey = PEM_read_PrivateKey(fp, 0, 0, (void*)*pPasswordBuffer);
		if (!privkey) {
			return bRC;
		}

		if (getPublicKey(privkey, bExp, bModulus)) {
			bExp.AssertIntegerPositivity();
			bModulus.AssertIntegerPositivity();
		
			bModulus.ASN1Wrap(UNIVERSAL_TYPE_INT);
			bExp.ASN1Wrap(UNIVERSAL_TYPE_INT);

			SubjUser.Clear();
			SubjCntry.Clear();
			SubjState.Clear();
			SubjCity.Clear();
			SubjOrg.Clear();
			SubjUnit.Clear();
			SubjAltName.Clear();

			SubjUser.Append((void*)subjUser, strlen(subjUser));
			SubjCntry.Append((void*)subjCntry, strlen(subjCntry));
			SubjState.Append((void*)subjState, strlen(subjState));
			SubjCity.Append((void*)subjCity, strlen(subjCity));
			SubjOrg.Append((void*)subjOrg, strlen(subjOrg));
			SubjUnit.Append((void*)subjUnit, strlen(subjUnit));
			SubjAltName.Append((void*)subjDNS, strlen(subjDNS));

			bRC = BuildServerCSR(privkey, bModulus, bExp, bCSR);
		}

		if (fp) {
			fclose(fp);
		}

		if (privkey) {
			EVP_PKEY_free(privkey);
		}
	}
	catch (...) {
		bCSR.Clear();

		if (fp) {
			fclose(fp);
		}

		if (privkey) {
			EVP_PKEY_free(privkey);
		}
		return FALSE;
	}

	return bRC;
#else
	return FALSE;
#endif
}
