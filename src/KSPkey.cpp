/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "Utils.h"
#include "x509class.h"
#include "RSAPublicKey.h"
#include "Utils.h"
#include "KSPkey.h"


using namespace ReiazDean;

mutex KSPkey::m_Mutex;

SECURITY_STATUS KSPkey::EnumProviders(Buffer& bProvs)
{
	SECURITY_STATUS ss = ERROR_SUCCESS;
	DWORD dwCount = 0;
	NCryptProviderName* pProviderList = nullptr;

	try {
		bProvs.Clear();

		ss = NCryptEnumStorageProviders(&dwCount, &pProviderList, NCRYPT_SILENT_FLAG);
		if (!pProviderList) {
			return NTE_FAIL;
		}

		for (DWORD i = 0; i < dwCount; i++) {
			bProvs.Append((void*)pProviderList[i].pszName, wcslen(pProviderList[i].pszName) * sizeof(WCHAR));
			bProvs.EOLN_w();
		}
		bProvs.NullTerminate_w();

		NCryptFreeBuffer(pProviderList);
		pProviderList = nullptr;
	}
	catch (...) {
		bProvs.Clear();
		if (pProviderList) {
			NCryptFreeBuffer(pProviderList);
		}
		return NTE_FAIL;
	}
	
	return ss;
}

SECURITY_STATUS KSPkey::EnumKeys(WCHAR* pwcProvider, Buffer& bKeys)
{
	SECURITY_STATUS ss = ERROR_SUCCESS;
	NCRYPT_PROV_HANDLE hProvider = 0;
	NCryptKeyName* pKeyName = nullptr;
	PVOID pEnumState = nullptr;
	DWORD dwFlags = NCRYPT_SILENT_FLAG;

	try {
		bKeys.Clear();

		ss = NCryptOpenStorageProvider(&hProvider, pwcProvider, 0);
		if (!hProvider) {
			return NTE_FAIL;
		}

		while (ERROR_SUCCESS == NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, dwFlags)) {
			bKeys.Append((void*)pKeyName->pszName, wcslen(pKeyName->pszName) * sizeof(WCHAR));
			bKeys.EOLN_w();
			NCryptFreeBuffer(pKeyName);
			pKeyName = nullptr;
		}
		bKeys.NullTerminate_w();

		if (pEnumState) {
			NCryptFreeBuffer(pEnumState);
			pEnumState = nullptr;
		}

		NCryptFreeObject(hProvider);
		hProvider = 0;
	}
	catch (...) {
		if (pEnumState) {
			NCryptFreeBuffer(pEnumState);
			pEnumState = nullptr;
		}

		if (pKeyName) {
			NCryptFreeBuffer(pKeyName);
			pKeyName = nullptr;
		}

		if (hProvider) {
			NCryptFreeObject(hProvider);
			hProvider = 0;
		}
		return NTE_FAIL;
	}

	return ss;
}

SECURITY_STATUS KSPkey::Encrypt(WCHAR* pwcProvName, WCHAR* pwcKeyName, Buffer& bPlain, Buffer& bEnc)
{
	try {
		KSPkey ksp((WCHAR*)pwcProvName);
		if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)pwcKeyName, 0)) {
			Buffer bPub;
			if (ERROR_SUCCESS == ksp.GetPublicKey(bPub)) {
				RSAPublicKey rsa((uint8_t*)bPub, bPub.Size());
				if (ERROR_SUCCESS == rsa.Encrypt((uint8_t*)bPlain, bPlain.Size(), bEnc)) {
					return ERROR_SUCCESS;
				}
			}
		}
	}
	catch (...) {
		bEnc.Clear();
		return NTE_FAIL;
	}

	return NTE_FAIL;
}

KSPkey::KSPkey()
{
	m_provH = 0;
	m_keyH = 0;
	m_alg = nullptr;
}

KSPkey::KSPkey(WCHAR* pwcProvider) : KSPkey()
{
	SECURITY_STATUS ss = ERROR_SUCCESS;
	ss = NCryptOpenStorageProvider(&m_provH, pwcProvider, 0);
}

KSPkey::~KSPkey()
{
	if (m_alg) {
		NCryptFreeBuffer(m_alg);
	}

	if (m_keyH) {
		NCryptFreeObject(m_keyH);
	}

	if (m_provH) {
		NCryptFreeObject(m_provH);
	}
}

SECURITY_STATUS KSPkey::OpenKeySilently(WCHAR* pwcKeyName, DWORD dwSpec, char* pcPin)
{
	SECURITY_STATUS ss = NTE_FAIL;
	try {
		Buffer b;
		
		if (m_provH == 0) {
			return NTE_BAD_PROVIDER;
		}

		ss = NCryptOpenKey(m_provH, &m_keyH, pwcKeyName, dwSpec, NCRYPT_SILENT_FLAG);

		if (ss == ERROR_SUCCESS) {
			GetWcharFromUtf8(pcPin, b);
			ss = NCryptSetProperty(m_keyH, NCRYPT_PIN_PROPERTY, (uint8_t*)b, b.Size(), 0);
		}

		if (ss == ERROR_SUCCESS) {
			std::unique_lock<std::mutex> mlock(m_Mutex);
			if (Password.Size() == 0) {
				Password.Append(pcPin, strlen(pcPin));
				Password.NullTerminate();
			}
		}
	}
	catch (...) {
		Password.Clear();
		return NTE_FAIL;
	}

	return ss;
}

SECURITY_STATUS KSPkey::OpenKey(WCHAR* pwcKeyName, DWORD dwSpec)
{
	SECURITY_STATUS ss = NTE_FAIL;
	try {
		BOOL bSilent = TRUE;
		DWORD dwFlags = 0;// NCRYPT_SILENT_FLAG;

		if (m_provH == 0) {
			return NTE_BAD_PROVIDER;
		}

		{
			std::unique_lock<std::mutex> mlock(m_Mutex);
			bSilent = (Password.Size() > 0);
		}

		if (bSilent) {
			ss = OpenKeySilently(pwcKeyName, dwSpec, (char*)Password);
		}
		else {
			ss = NCryptOpenKey(m_provH, &m_keyH, pwcKeyName, dwSpec, dwFlags);
		}
	}
	catch (...) {
		return NTE_FAIL;
	}

	return ss;
}

SECURITY_STATUS KSPkey::CreateKey(WCHAR* pwcKeyName, DWORD dwSpec)
{
	SECURITY_STATUS ss = NTE_FAIL;
	DWORD dwFlags = 0;// NCRYPT_SILENT_FLAG;
	NCRYPT_KEY_HANDLE hKey = 0;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	ss = NCryptCreatePersistedKey(m_provH, &hKey, L"RSA", pwcKeyName, 0, NCRYPT_OVERWRITE_KEY_FLAG*0);
	if (ERROR_SUCCESS == ss) {
		DWORD	dwKeyBits = 2048;
		ss = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (BYTE*)&dwKeyBits, sizeof(DWORD), 0);
		if (ERROR_SUCCESS == ss) {
			DWORD dwUsg = dwSpec;
			ss = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (BYTE*)&dwUsg, sizeof(DWORD), 0);
		}

		if (ERROR_SUCCESS == ss) {
			ss = NCryptFinalizeKey(hKey, 0);
		}
	}

	return ss;
}

SECURITY_STATUS KSPkey::DestroyKey(WCHAR* pwcKeyName)
{
	SECURITY_STATUS ss = NTE_FAIL;
	DWORD dwFlags = 0;// NCRYPT_SILENT_FLAG;
	NCRYPT_KEY_HANDLE hKey = 0;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	ss = NCryptOpenKey(m_provH, &hKey, pwcKeyName, AT_SIGNATURE, dwFlags);
	if (ss != ERROR_SUCCESS) {
		hKey = 0;
		ss = NCryptOpenKey(m_provH, &hKey, pwcKeyName, AT_KEYEXCHANGE, dwFlags);
	}
	if (ss != ERROR_SUCCESS) {
		hKey = 0;
		ss = NCryptOpenKey(m_provH, &hKey, pwcKeyName, 0, dwFlags);
	}

	if (ss == ERROR_SUCCESS) {
		ss = NCryptDeleteKey(hKey, dwFlags);
	}

	return ss;
}

SECURITY_STATUS KSPkey::GetPublicKey(Buffer& bKey)
{
	DWORD dwSize = 0;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	if (m_keyH == 0) {
		return NTE_BAD_KEY;
	}

	try {
		bKey.Clear();
		if (ERROR_SUCCESS == NCryptExportKey(m_keyH, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &dwSize, 0)) {
			Buffer b(dwSize);
			if (ERROR_SUCCESS == NCryptExportKey(m_keyH, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, (uint8_t*)b, dwSize, &dwSize, 0)) {
				bKey.Append((void*)b, dwSize);
				return ERROR_SUCCESS;
			}
		}
	}
	catch (...) {
		bKey.Clear();
		return NTE_FAIL;
	}

	return NTE_FAIL;
}

SECURITY_STATUS KSPkey::GetCertificate(Buffer& bCert)
{
	DWORD cbOutput = 0;
	DWORD dwFlags = NCRYPT_SILENT_FLAG;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	if (m_keyH == 0) {
		return NTE_BAD_KEY;
	}

	try {
		if (ERROR_SUCCESS == NCryptGetProperty(m_keyH, NCRYPT_CERTIFICATE_PROPERTY, NULL, 0, &cbOutput, dwFlags)) {
			Buffer b(cbOutput);
			if (ERROR_SUCCESS == NCryptGetProperty(m_keyH, NCRYPT_CERTIFICATE_PROPERTY, (uint8_t*)b, cbOutput, &cbOutput, dwFlags)) {
				bCert.Append((uint8_t*)b, cbOutput);
				return ERROR_SUCCESS;
			}
		}
	}
	catch (...) {
		bCert.Clear();
		return NTE_FAIL;
	}

	return NTE_FAIL;
}

SECURITY_STATUS KSPkey::SetCertificate(Buffer& bCert)
{
	DWORD cbOutput = 0;
	DWORD dwFlags = 0;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	if (m_keyH == 0) {
		return NTE_BAD_KEY;
	}

	try {
		return NCryptSetProperty(m_keyH, NCRYPT_CERTIFICATE_PROPERTY, (uint8_t*)bCert, bCert.Size(), dwFlags);
	}
	catch (...) {
		return NTE_FAIL;
	}

	return NTE_FAIL;
}

DWORD KSPkey::GetLength()
{
	DWORD cbOutput = 0;
	DWORD dwFlags = NCRYPT_SILENT_FLAG;
	DWORD dwLen = 0;

	if (ERROR_SUCCESS == NCryptGetProperty(m_keyH, NCRYPT_LENGTH_PROPERTY, (uint8_t*)&dwLen, sizeof(DWORD), &cbOutput, dwFlags)) {
		return dwLen;
	}

	return 0;
}
SECURITY_STATUS KSPkey::GetProperty(WCHAR* pwcProp, Buffer& bProp)
{
	DWORD cbOutput = 0;
	DWORD dwFlags = NCRYPT_SILENT_FLAG;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	if (m_keyH == 0) {
		return NTE_BAD_KEY;
	}

	try {
		if (ERROR_SUCCESS == NCryptGetProperty(m_keyH, pwcProp, NULL, 0, &cbOutput, dwFlags)) {
			Buffer b(cbOutput);
			if (ERROR_SUCCESS == NCryptGetProperty(m_keyH, pwcProp, (uint8_t*)b, cbOutput, &cbOutput, dwFlags)) {
				bProp.Append((uint8_t*)b, cbOutput);
				return ERROR_SUCCESS;
			}
		}
	}
	catch (...) {
		bProp.Clear();
		return NTE_FAIL;
	}

	return NTE_FAIL;
}

SECURITY_STATUS KSPkey::SignHash(uint8_t* pcHash, int32_t szHash, Buffer& bSig)
{
	DWORD dwSize = 0;
	SECURITY_STATUS ss = NTE_FAIL;
	BCRYPT_PKCS1_PADDING_INFO pi;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	if (m_keyH == 0) {
		return NTE_BAD_KEY;
	}

	switch (szHash) {
	case 32:
		pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		break;
	case 48:
		pi.pszAlgId = BCRYPT_SHA384_ALGORITHM;
		break;
	case 64:
		pi.pszAlgId = BCRYPT_SHA512_ALGORITHM;
		break;
	default:
		return NTE_FAIL;
	}

	try {
		bSig.Clear();
		ss = NCryptSignHash(m_keyH, &pi, pcHash, szHash, NULL, 0, &dwSize, BCRYPT_PAD_PKCS1);
		if (ERROR_SUCCESS == ss) {
			Buffer bTmp(dwSize);
			ss = NCryptSignHash(m_keyH, &pi, pcHash, szHash, (uint8_t*)bTmp, dwSize, &dwSize, BCRYPT_PAD_PKCS1);
			if (ERROR_SUCCESS == ss) {
				bSig.Append((uint8_t*)bTmp, dwSize);
			}
		}
	}
	catch (...) {
		bSig.Clear();
		return NTE_FAIL;
	}

	return ss;
}

SECURITY_STATUS KSPkey::Decrypt(uint8_t* ciphertext, int32_t len, Buffer& bPlain)
{
	DWORD dwSize = 0;
	SECURITY_STATUS ss = NTE_FAIL;

	if (m_provH == 0) {
		return NTE_BAD_PROVIDER;
	}

	if (m_keyH == 0) {
		return NTE_BAD_KEY;
	}

	try {
		bPlain.Clear();
		ss = NCryptDecrypt(m_keyH, ciphertext, len, NULL, NULL, 0, &dwSize, BCRYPT_PAD_PKCS1);
		if (ERROR_SUCCESS == ss) {
			Buffer bTmp(dwSize);
			ss = NCryptDecrypt(m_keyH, ciphertext, len, NULL, (uint8_t*)bTmp, dwSize, &dwSize, BCRYPT_PAD_PKCS1);
			if (ERROR_SUCCESS == ss) {
				bPlain.Append((uint8_t*)bTmp, dwSize);
			}
		}
	}
	catch (...) {
		bPlain.Clear();
		return NTE_FAIL;
	}
	
	return ss;
}