/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include <WinSock2.h>
#include "SequenceReader.h"
#include "NdacConfig.h"
#include "LocalClient.h"
#include "DocHandler.h"

#define        FILE_READ_SZ   2048
#define        MAX_FILE_SIZE  0x20000000
#define        NON_BLOCK_TO   10

using namespace ReiazDean;

#ifndef AUTH_SERVICE
void SetLocalStatus(WCHAR* pwcText, bool bAppend);
extern int SandBoxedState;
extern LocalClient* MyLocalClient;
#endif

DocHandler::DocHandler() {
	m_MLS = 0;
	m_FP = nullptr;
	m_EncryptedSz = 0;
	m_FileSz = 0;
	m_Verified = false;
	m_LockHandle = INVALID_HANDLE_VALUE;
}

DocHandler::~DocHandler() {
	if (m_LockHandle != INVALID_HANDLE_VALUE) {
		UnlockEntireFile(m_LockHandle);
	}
	Close();
}

void DocHandler::Close() {
	if (m_FP) {
		fclose(m_FP);
		m_FP = nullptr;
	}
}

bool
DocHandler::OpenUnprotectedDocument(wchar_t* pcDocName, bool bLock) {
	struct _stat sbuf;

	if (!pcDocName) {
		return false;
	}

#ifdef AUTH_SERVICE
	if (bLock) {
		m_LockHandle = LockFilePath(pcDocName);
		if (m_LockHandle == INVALID_HANDLE_VALUE) {
			return false;
		}
	}
#endif

	_wstat((wchar_t*)pcDocName, &sbuf);
	if (sbuf.st_size > 0)
	{
		m_FileSz = sbuf.st_size;
		m_FP = f_open_u(pcDocName, (wchar_t*)L"rb");
	}

	return (m_FP != 0);
}

bool
DocHandler::OpenDocument(wchar_t* pcDocName, bool bLock) {
	struct _stat sbuf;

	if (!pcDocName) {
		return false;
	}

#ifdef AUTH_SERVICE
	if (bLock) {
		m_LockHandle = LockFilePath(pcDocName);
		if (m_LockHandle == INVALID_HANDLE_VALUE) {
			return false;
		}
	}
#endif

	try {
		_wstat((wchar_t*)pcDocName, &sbuf);
		if (sbuf.st_size > 0)
		{
			m_FileSz = sbuf.st_size;
			m_FP = f_open_u(pcDocName, (wchar_t*)L"rb");
		}

		if (m_FP) {
			wchar_t* tok = nullptr;
			wchar_t* last = nullptr;
			wchar_t* name = nullptr;
			Buffer buf;
#ifdef OS_WIN32
			const wchar_t seps[] = L"\\";
#else
			const wchar_t seps[] = L"/";
#endif
			buf.Append((void*)pcDocName, wcslen(pcDocName) * sizeof(wchar_t));
			buf.NullTerminate_w();
			tok = wcstok_s((wchar_t*)buf, (wchar_t*)seps, &last);
			while (tok && last) {
				name = tok;
				tok = wcstok_s(0, (wchar_t*)seps, &last);
			}
			if (!name) {
				return false;
			}

			m_Name.Append((void*)name, wcslen(name) * sizeof(wchar_t));
			m_Name.NullTerminate_w();
			fread((char*)&m_EncryptedSz, 1, sizeof(m_EncryptedSz), m_FP);
#ifndef _BIG_ENDIAN
			ReverseMemory((uint8_t*)&m_EncryptedSz, sizeof(m_EncryptedSz));
#endif
			if ((m_EncryptedSz > 0) && (m_EncryptedSz < MAX_FILE_SIZE)) {
				return readHeader();
			}
		}
		return false;
	}
	catch (...) {
		m_Name.Clear();
		m_EncryptedSz = 0;
		return false;
	}
}

bool
DocHandler::readDocCertAndSig() {
	uint32_t   len;
	int      ch;
	uint32_t   certSz;
	uint32_t   sigSz;

	try {
		ch = fgetc(m_FP);
		if (ch != CONSTRUCTED_SEQUENCE) {//must be a constructed sequence
			return false;
		}
		len = ReadEncodedLength(m_FP);//the sequence length

		//read the wrapped certificate
		ch = fgetc(m_FP);
		if (ch != UNIVERSAL_TYPE_OCTETSTR) {
			return false;
		}
		certSz = ReadEncodedLength(m_FP);
		if (certSz > 0) {
			Buffer b(certSz);
			fread((char*)b, 1, certSz, m_FP);
			m_Certificate.Append((uint8_t*)b, certSz);
		}

		//read the wrapped signature
		ch = fgetc(m_FP);
		if (ch != UNIVERSAL_TYPE_OCTETSTR) {
			return false;
		}
		sigSz = ReadEncodedLength(m_FP);
		if (sigSz > 0) {
			Buffer b(sigSz);
			fread((char*)b, 1, sigSz, m_FP);
			m_Signature.Append((uint8_t*)b, sigSz);
		}

		//read the time stamped signature
		ch = fgetc(m_FP);
		if (ch != CONSTRUCTED_SEQUENCE) {
			return false;
		}
		sigSz = ReadEncodedLength(m_FP);
		if (sigSz > 0) {
			Buffer b(sigSz);
			fread((char*)b, 1, sigSz, m_FP);
			m_TimeStampSignature.Append((uint8_t*)b, sigSz);
			m_TimeStampSignature.ASN1Wrap(CONSTRUCTED_SEQUENCE);
		}

		return true;
	}
	catch (...) {
		m_Certificate.Clear();
		m_Signature.Clear();
		m_TimeStampSignature.Clear();
		return false;
	}

	return false;
}

bool
DocHandler::readHeader() {
	wchar_t buf[FILE_READ_SZ];
	wchar_t* tok = nullptr;
	wchar_t* last = nullptr;

	try {
		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1, m_FP);
		if (wcscmp((wchar_t*)buf, L"RDC\n") != 0) {
			return false;
		}

		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1, m_FP);
		if (wcsncmp((wchar_t*)buf, (wchar_t*)L"Version=", wcslen(L"Version=")) == 0) {
			m_Version.Append(buf, wcslen(buf) * sizeof(wchar_t));
			m_Version.NullTerminate_w();
		}
		else {
			return false;
		}

		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1 - 1, m_FP);
		if (wcsncmp((wchar_t*)buf, (wchar_t*)L"Application=", wcslen(L"Application=")) == 0) {
			tok = wcstok_s((wchar_t*)buf, (wchar_t*)L"=\n", &last);
			if (tok) {
				tok = wcstok_s(0, (wchar_t*)L"=\n", &last);
				if (tok) {
					m_Application.Append(tok, wcslen(tok) * sizeof(wchar_t));
					m_Application.NullTerminate_w();
				}
			}
		}
		else {
			return false;
		}

		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1, m_FP);
		if (wcsncmp((wchar_t*)buf, (wchar_t*)L"MLS=", wcslen(L"MLS=")) == 0) {
			tok = wcstok_s((wchar_t*)buf, (wchar_t*)L"=\n", &last);
			if (tok) {
				tok = wcstok_s(0, (wchar_t*)L"=\n", &last);
				if (tok) {
					m_MLS = _wtoi((wchar_t*)tok);
				}
			}
		}
		else {
			return false;
		}

		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1, m_FP);
		if (wcsncmp((wchar_t*)buf, (wchar_t*)L"MCS=", wcslen(L"MCS=")) == 0) {
			char mcs[MAX_MCS_LEVEL];
			memset(mcs, 0, sizeof(mcs));
			tok = wcstok_s((wchar_t*)buf, (wchar_t*)L"=", &last);
			if (tok) {
				tok = wcstok_s(0, (wchar_t*)L"=", &last);
			}
			if (tok) {
				tok = wcstok_s(tok, (wchar_t*)L",\n", &last);
			}
			while (tok) {
				int i = _wtoi((wchar_t*)tok);
				if (i >= 0 && i < MAX_MCS_LEVEL) {
					mcs[i] = 1;
				}
				tok = wcstok_s(0, (wchar_t*)L",\n", &last);
			}
			m_MCS.Append(mcs, sizeof(mcs));
		}
		else {
			return false;
		}

		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1, m_FP);
		if (wcsncmp((wchar_t*)buf, (wchar_t*)L"Document Label=", wcslen(L"Document Label=")) == 0) {
			m_Label.Append((wchar_t*)buf, wcslen((wchar_t*)buf) * sizeof(wchar_t));
			m_Label.NullTerminate_w();
		}
		else {
			return false;
		}

		memset(buf, 0, sizeof(buf));
		fgetws(buf, FILE_READ_SZ - 1, m_FP);
		if (wcsncmp((wchar_t*)buf, (wchar_t*)L"HsmKeyName=", wcslen(L"HsmKeyName=")) == 0) {
			tok = wcstok_s((wchar_t*)buf, (wchar_t*)L"=\n", &last);
			if (tok) {
				tok = wcstok_s(0, (wchar_t*)L"=\n", &last);
				if (tok) {
					Buffer b;
					m_HsmKeyName.Append((void*)tok, wcslen(tok) * sizeof(wchar_t));
					m_HsmKeyName.NullTerminate_w();
				}
			}
		}
		else {
			return false;
		}

		return true;
	}
	catch (...) {
		m_HsmKeyName.Clear();
		m_Label.Clear();
		m_MCS.Clear();
		m_MLS = 0;
		m_Application.Clear();
		m_Version.Clear();
		return false;
	}

	return false;
}

bool
DocHandler::GetAuthRequest(AuthorizationRequest& ar) {
	try {
		memset(&ar, 0, sizeof(ar));
		memcpy((void*)ar.docMAC.mls_doc_name, (wchar_t*)m_Name, m_Name.Size());
		ar.docMAC.mls_level = m_MLS;
		ar.docMAC.mls_doc_size = m_FileSz;
		for (int i = 0; i < MAX_MCS_LEVEL; i++) {
			ar.docMAC.mcs[i] = m_MCS[i];
		}
		memcpy(ar.hsmKeyName, (void*)m_HsmKeyName, wcslen(m_HsmKeyName) * sizeof(WCHAR));

		return true;
	}
	catch (...) {
		memset(&ar, 0, sizeof(ar));
		return false;
	}

	return false;
}

void
DocHandler::SetAuthResponse(const AuthorizationResponse& ar) {
	try {
		m_AuthResponse.Clear();
		m_AuthResponse.Append((void*)&ar, sizeof(ar));
	}
	catch (...) {
		m_AuthResponse.Clear();
	}
}

uint32_t
DocHandler::wrapClientCertAndSig(Buffer& bHash, Buffer& bCertAndSig)
{
#ifndef AUTH_SERVICE
	try {
		if (SandBoxedState == NdacClientConfig::SandboxedState::INSIDE) {
			if (MyLocalClient) {
				Buffer bTmp;
				CommandHeader ch;
				Buffer bCmd;

				bTmp.Append((void*)&m_EncryptedSz, sizeof(m_EncryptedSz));
				bTmp.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
				bHash.ASN1Wrap(UNIVERSAL_TYPE_OCTETSTR);
				bHash.Append(bTmp);
				bHash.ASN1Wrap(CONSTRUCTED_SEQUENCE);

				ch.command = CMD_OOB_SC_SIGN_DOC_HASH;
				ch.szData = bHash.Size();

				bCmd.Append((void*)&ch, sizeof(ch));
				bCmd.Append(bHash);

				if (RSP_SUCCESS == MyLocalClient->SendToProxy(bCmd, bCertAndSig)) {
					return bCertAndSig.Size();
				}

				return 0;
			}

			return 0;
		}
		else {
			return KSPwrapClientCertAndSigForDoc(ChooseUserKey(), (uint8_t*)bHash, bHash.Size(), m_EncryptedSz, bCertAndSig);
		}
	}
	catch (...) {
		bHash.Clear();
		bCertAndSig.Clear();
		return 0;
	}
#else
	return -1;
#endif
}

bool
DocHandler::ProtectFile(
	wchar_t* sDocName,
	wchar_t* outDoc,
	wchar_t* sApp,
	std::shared_ptr<NotifyView> notifier)
{
	float percent = 0.0;
	bool bRc = false;
	size_t r = 0;
	char buf[FILE_ENCRYPTION_SZ];
	FILE* in = 0;
	FILE* out = 0;
	wstring header = L"RDC\n";
	Buffer bHash;
	Buffer bASN;
	uint32_t szASN = 0;
	struct _stat sbuf;

	try {
		_wstat((wchar_t*)sDocName, &sbuf);
		if (sbuf.st_size > 0) {
			in = f_open_u(sDocName, (wchar_t*)L"rb");
			out = f_open_u(outDoc, (wchar_t*)L"wb");
		}

		if (in && out) {
			AuthorizationResponse* pAR = (AuthorizationResponse*)m_AuthResponse;
			uint8_t* encryptionKey;
			size_t headerSz = 0;
			m_EncryptedSz = 0;
			fwrite(&m_EncryptedSz, 1, sizeof(m_EncryptedSz), out);
			header += L"Version=0.0.1\n";
			header += L"Application=";
			header += sApp;
			header += L"\n";
			header += printAR(pAR);

			//printf("header = \n%S\n", header.c_str());
			headerSz = header.size() * sizeof(wchar_t);
			if (fwrite(header.c_str(), 1, headerSz, out) != headerSz) {
				fclose(in);
				fclose(out);
				return false;
			}

			bHash.Clear();
			bHash.Append((char*)"ReiazDean", 9);
			encryptionKey = (uint8_t*)pAR->encryptionKey;
			do {
				memset(buf, 0, FILE_ENCRYPTION_SZ);
				r = fread(buf, 1, FILE_ENCRYPTION_SZ, in);
				if (r > 0) {
					uint32_t rr = (uint32_t)r;
					Buffer bIn;
					Buffer bEnc;
					if (AES_CBC_Encrypt(encryptionKey, encryptionKey + AES_256_KEY_SZ, (uint8_t*)buf, rr, bEnc) == 0) {
						fclose(in);
						fclose(out);
						return false;
					}

					bIn.Append(bHash);
					bIn.Append(buf, rr);//bIn.Append(bEnc, bEnc.Size());
					if (Sha256((uint8_t*)bIn, bIn.Size(), bHash) != SHA256_DIGEST_LENGTH) {
						fclose(in);
						fclose(out);
						return false;
					}

					if (fwrite((char*)bEnc, 1, bEnc.Size(), out) != bEnc.Size()) {
						fclose(in);
						fclose(out);
						return false;
					}

					m_EncryptedSz += bEnc.Size();

					if (notifier && notifier->function && notifier->hWnd) {
						float pcent = ((float)m_EncryptedSz / (float)sbuf.st_size) * (float)100.0;
						float diff = pcent - percent;
						if (diff > 1.0) {
#ifndef AUTH_SERVICE
							WCHAR msg[64];
							swprintf_s(msg, 64, L"Percent encrypted: %f\n", pcent);
							SetLocalStatus(msg, false);
#endif
							percent = pcent;
							notifier->function(notifier->hWnd);
						}
					}
				}
			} while (r == FILE_ENCRYPTION_SZ);

			bASN.Clear();
			szASN = wrapClientCertAndSig(bHash, bASN);
			if (szASN > 0) {
				if (fwrite((char*)bASN, 1, szASN, out) == szASN) {
					if (fseek(out, 0, SEEK_SET) == 0) {
#ifndef _BIG_ENDIAN
						ReverseMemory((uint8_t*)&m_EncryptedSz, sizeof(m_EncryptedSz));
#endif
						fwrite(&m_EncryptedSz, 1, sizeof(m_EncryptedSz), out);
						bRc = true;
					}
				}
			}
		}

		if (in) {
			fclose(in);
		}

		if (out) {
			fclose(out);
		}

		return bRc;
	}
	catch (...) {
		if (in) {
			fclose(in);
		}

		if (out) {
			fclose(out);
		}

		return false;
	}
}

bool
DocHandler::DecryptVerify(FILE* fOut, std::shared_ptr<NotifyView> notifier)
{
	uint32_t chunks = m_EncryptedSz / (FILE_DECRYPTION_SZ);//4112
	uint32_t remains = m_EncryptedSz % (FILE_DECRYPTION_SZ);
	
	try {
		if (m_FP) {
			uint32_t total = 0;
			float percent = 0.0;
			int ret = 0;
			size_t r = 0;
			Buffer bHash;
			DWORD dwMShash = 64;
			uint8_t* decryptionKey = nullptr;
			AuthorizationResponse* pAR = (AuthorizationResponse*)m_AuthResponse;

			bHash.Clear();
			bHash.Append((char*)"ReiazDean", 9);
			decryptionKey = (uint8_t*)pAR->decryptionKey;
			for (uint32_t i = 0; i < chunks; i++) {
				Buffer bEnc(FILE_DECRYPTION_SZ);
				Buffer bPlain;
				r = fread((char*)bEnc, 1, FILE_DECRYPTION_SZ, m_FP);
				if (r > 0) {
					uint32_t rr = (uint32_t)r;
					if (AES_CBC_Decrypt(decryptionKey, decryptionKey + AES_256_KEY_SZ, (uint8_t*)bEnc, rr, bPlain) > 0) {
						Buffer bIn;
						bIn.Clear();
						bIn.Append(bHash);
						bIn.Append(bPlain);
						Sha256((uint8_t*)bIn, bIn.Size(), bHash);
						if (fOut) {
							fwrite((char*)bPlain, 1, bPlain.Size(), fOut);
						}
					}
					total += rr;
				}
				
				if (notifier && notifier->function && notifier->hWnd) {
					float pcent = ((float)total / (float)m_EncryptedSz) * (float)100.0;
					float diff = pcent - percent;
					if (diff > 1.0) {
#ifndef AUTH_SERVICE
						WCHAR msg[64];
						swprintf_s(msg, 64, L"Percent %s: %f\n", (fOut ? L"decrypted" : L"verified"), pcent);
						SetLocalStatus(msg, false);
#endif
						percent = pcent;
						notifier->function(notifier->hWnd);
					}
				}
			}

			if (remains > 0) {
				Buffer bEnc(remains);
				Buffer bPlain;
				r = fread((char*)bEnc, 1, remains, m_FP);
				if (r > 0) {
					uint32_t rr = (uint32_t)r;
					if (AES_CBC_Decrypt(decryptionKey, decryptionKey + AES_256_KEY_SZ, (uint8_t*)bEnc, rr, bPlain) > 0) {
						Buffer bIn;
						bIn.Clear();
						bIn.Append(bHash);
						bIn.Append(bPlain);
						Sha256((uint8_t*)bIn, bIn.Size(), bHash);
						if (fOut) {
							fwrite((char*)bPlain, 1, bPlain.Size(), fOut);
						}
					}
				}
			}

			{
				Buffer bIn;
				bIn.Clear();
				bIn.Append(bHash);
				Sha256((uint8_t*)bIn, bIn.Size(), bHash);
			}

			if (readDocCertAndSig()) {
				ret = VerifySignatureCNG(m_Certificate, (uint8_t*)bHash, bHash.Size(), (uint8_t*)m_Signature, m_Signature.Size());

				if (ret == 1) {
#ifdef AUTH_SERVICE
					NdacServerConfig& nc = NdacServerConfig::GetInstance();
#else
					NdacClientConfig& nc = NdacClientConfig::GetInstance();
#endif
					Buffer caCertBundle;
					caCertBundle.Clear();
					nc.GetValue(TRUSTED_CA_FILE, caCertBundle);
					m_Verified = TLSContext::VerifyCertWithBundle((char*)caCertBundle, (uint8_t*)m_Certificate, m_Certificate.Size());
				}

				if (notifier && notifier->function && notifier->hWnd) {
					notifier->function(notifier->hWnd);
				}
			}
		}

		return m_Verified;
	}
	catch (...) {
		return false;
	}
}

bool
DocHandler::GetTimeStamp(time_t& when) {
	try {
		if (m_TimeStampSignature.Size() > 0) {
			SequenceReaderX seq;
			Buffer bNow;
			if (seq.Initilaize(m_TimeStampSignature)) {
				if (seq.getValueAt(0, bNow)) {
					if (bNow.Size() == sizeof(time_t)) {
						memcpy(&when, (void*)bNow, bNow.Size());
						return true;
					}
				}
			}
		}
	}
	catch (...) {
		return false;
	}

	return false;
}

bool
DocHandler::TimeStampVerify(DilithiumKeyPair& dilKey) {
	int ret = -1;
	bool verified = false;

	try {
		if (m_FP) {
			if (fseek(m_FP, m_EncryptedSz, SEEK_CUR) == 0) {
				if (readDocCertAndSig()) {
					SequenceReaderX seq;
					Buffer bHash;
					Buffer bTemp(m_Signature);
					if (seq.Initilaize(m_TimeStampSignature)) {
						Buffer bNow;
						if (seq.getElementAt(0, bNow)) {
							Buffer bTSsig;
							if (seq.getValueAt(1, bTSsig)) {
								bTemp.Append(bNow);
								verified = dilKey.Verify(bTemp, bTSsig);
							}
						}
					}
				}
			}
		}

		return verified;
	}
	catch (...) {
		return false;
	}
}

Responses
DocHandler::SendDocument(TLSContext& tls, std::shared_ptr<NotifyView> notifier) {
	uint32_t total = 0;
	float percent = 0.0;
	size_t r = 0;
	Buffer bHash;
	
	if (!m_FP) {
		return RSP_FILE_ERROR;
	}

	try {
		bHash.Clear();
		bHash.Append((char*)"ReiazDean", 9);
		fseek(m_FP, 0, SEEK_SET);
		do {
			uint32_t rr = 0;
			Buffer a(FILE_TRANSFER_CHUNK_SZ);
			r = fread((void*)a, 1, FILE_TRANSFER_CHUNK_SZ, m_FP);
			rr = (uint32_t)r;
			if (r > 0) {
				Buffer b((void*)a, rr);
				Buffer bIn;
				bIn.Append(bHash);
				bIn.Append((void*)b, rr);
				if (Sha256((uint8_t*)bIn, bIn.Size(), bHash) != SHA256_DIGEST_LENGTH) {
					return RSP_DIGEST_ERROR;
				}
				
				if (tls.DoNonBlockingWrite(b) <= 0) {
					return RSP_SOCKET_IO_ERROR;
				}

				total += rr;
				if (notifier && notifier->function && notifier->hWnd) {
					float pcent = ((float)total / (float)(m_FileSz)) * (float)100.0;
					float diff = pcent - percent;
					if (diff > 1.0) {
#ifndef AUTH_SERVICE
						WCHAR msg[64];
						swprintf_s(msg, 64, L"Percent uploaded: %f\n", pcent);
						SetLocalStatus(msg, false);
#endif
						percent = pcent;
						notifier->function(notifier->hWnd);
					}
				}
			}
		} while (total < m_FileSz);

		{
			//wait for the receiver to signal back so we may send the hash
			Buffer b;
			if (tls.DoNonBlockingRead(b) <= 0) {
				return RSP_SOCKET_IO_ERROR;
			}
		}

		if (tls.DoNonBlockingWrite(bHash) != SHA256_DIGEST_LENGTH) {
			return RSP_SOCKET_IO_ERROR;
		}

		return RSP_SUCCESS;
	}
	catch (...) {
		return RSP_FILE_ERROR;
	}
}

Responses
DocHandler::ReceiveDocument(
	TLSContext& tls,
	wchar_t* filename,
	wchar_t* tempfname,
	int32_t len,
	std::shared_ptr<NotifyView> notifier)
{
	int32_t total = 0;
	float percent = 0.0;
	int r = -1;
	Buffer bHash;
	Buffer bOtherHash;
	FILE* fp = f_open_u(tempfname, (wchar_t*)L"wb");
	if (!fp) {
		return RSP_FILE_ERROR;
	}

	try {
		bHash.Clear();
		bHash.Append((char*)"ReiazDean", 9);

		do {
			Buffer b;
			r = tls.DoNonBlockingReadEx(b);
			if (r == 0) {
				continue;
			}
			else if (r < 0) {
				fclose(fp);
				DeleteFileW(tempfname);
				return RSP_COMMAND_TIMEOUT;
			}
			else {
				Buffer bIn;
				uint32_t rr = r;
				bIn.Append(bHash);
				bIn.Append((void*)b, rr);
				if (Sha256((uint8_t*)bIn, bIn.Size(), bHash) != SHA256_DIGEST_LENGTH) {
					fclose(fp);
					return RSP_DIGEST_ERROR;
				}
				fwrite((void*)b, r, 1, fp);
				total += rr;
				if (notifier && notifier->function && notifier->hWnd) {
					float pcent = ((float)total / (float)(len)) * (float)100.0;
					float diff = pcent - percent;
					if (diff >= 1.0f) {
#ifndef AUTH_SERVICE
						WCHAR msg[64];
						swprintf_s(msg, 64, L"Percent downloaded: %f of %d bytes\n", pcent, len);
						SetLocalStatus(msg, false);
#endif
						percent = pcent;
						notifier->function(notifier->hWnd);
					}
				}
			}
		} while (total < len);

		fclose(fp);
		fp = 0;
	}
	catch (...) {
		if (fp) {
			fclose(fp);
		}
		DeleteFileW(tempfname);
		return RSP_FILE_ERROR;
	}

#ifndef AUTH_SERVICE
	WCHAR msg[64];
	swprintf_s(msg, 64, L"Total %u of %u downloaded\n", total, len);
	SetLocalStatus(msg, true);
#else
	//printf("Total %d of %d uploaded\n", total, len);
#endif

	try {
		{
			//signal the sender it may send the hash
			Buffer b((void*)&r, sizeof(r));
			tls.DoNonBlockingWrite(b);
		}

		r = tls.DoNonBlockingRead(bOtherHash);
		if (r != SHA256_DIGEST_LENGTH) {
			DeleteFileW(tempfname);
			return RSP_SOCKET_IO_ERROR;
		}

		if (memcmp((void*)bHash, (void*)bOtherHash, SHA256_DIGEST_LENGTH) != 0) {
			return RSP_HASH_MISMATCH;
		}

		DeleteFileW(filename);
		if (!MoveFileW(tempfname, filename)) {
			DeleteFileW(tempfname);
			return RSP_FILE_MOVE_ERROR;
		}
	}
	catch (...) {
		return RSP_SOCKET_IO_ERROR;
	}

	return RSP_SUCCESS;
}

/*
* Outside the sandbox, the client will receive from the sandboxed client and send to the Auth service
*/
Responses
DocHandler::ProxyReceiveSendDocument(TLSContext& tls, SOCKET sbSocket, int32_t len)
{
	int r = -1;
	int32_t total = 0;
	Buffer bHash;

	try {
		do {
			Buffer b;
			r = NonBlockingRead(sbSocket, b);
			if (r <= 0) {
				return RSP_SOCKET_IO_ERROR;
			}
			total += (int32_t)r;
			if (r != tls.DoNonBlockingWrite(b)) {
				return RSP_SOCKET_IO_ERROR;
			}
		} while (total < len);

		if (NonBlockingWriteEx(sbSocket, (char*)&r, sizeof(int)) == 0) {
			return RSP_SOCKET_IO_ERROR;
		}

		if (SHA256_DIGEST_LENGTH != NonBlockingRead(sbSocket, bHash)) {
			return RSP_HASH_MISMATCH;
		}

		if (SHA256_DIGEST_LENGTH != tls.DoNonBlockingWrite(bHash)) {
			return RSP_SOCKET_IO_ERROR;
		}

		return RSP_SUCCESS;
	}
	catch (...) {
		return RSP_SOCKET_IO_ERROR;
	}
}

/*
* Inside the sandbox, the client will send to the proxy client outside the sandbox
*/
Responses
DocHandler::SendDocumentToProxy(SOCKET sbSock, std::shared_ptr<NotifyView> notifier)
{
	uint32_t total = 0;
	float percent = 0.0;
	size_t r = 0;
	Buffer sig;
	Buffer bHash;

	if (!m_FP) {
		return RSP_FILE_ERROR;
	}

	try {
		bHash.Clear();
		bHash.Append((char*)"ReiazDean", 9);
		fseek(m_FP, 0, SEEK_SET);
		do {
			uint32_t rr = 0;
			Buffer a(FILE_TRANSFER_CHUNK_SZ);
			r = fread((void*)a, 1, FILE_TRANSFER_CHUNK_SZ, m_FP);
			rr = (uint32_t)r;
			if (rr > 0) {
				Buffer b((void*)a, rr);
				Buffer bIn;
				bIn.Append(bHash);
				bIn.Append((void*)b, rr);
				if (Sha256((uint8_t*)bIn, bIn.Size(), bHash) != SHA256_DIGEST_LENGTH) {
					return RSP_DIGEST_ERROR;
				}
				total += rr;

				if (NonBlockingWrite(sbSock, b) < 0) {
					return RSP_SOCKET_IO_ERROR;
				}

				if (notifier && notifier->function && notifier->hWnd) {
					float pcent = ((float)total / (float)(m_FileSz)) * (float)100.0;
					float diff = pcent - percent;
					if (diff > 1.0) {
#ifndef AUTH_SERVICE
						WCHAR msg[64];
						swprintf_s(msg, 64, L"Percent uploaded: %f len = %u\n", pcent, m_FileSz);
						SetLocalStatus(msg, false);
#endif
						percent = pcent;
						notifier->function(notifier->hWnd);
					}
				}
			}
		} while (total < m_FileSz);

		if (NonBlockingRead(sbSock, sig) == 0) {
			return RSP_SOCKET_IO_ERROR;
		}

		if (NonBlockingWrite(sbSock, bHash) != SHA256_DIGEST_LENGTH) {
			return RSP_HASH_MISMATCH;
		}
	}
	catch (...) {
		return RSP_SOCKET_IO_ERROR;
	}

	return RSP_SUCCESS;
}

Responses
DocHandler::ReceiveDocumentFromProxy(
	SOCKET sock,
	wchar_t* filename,
	wchar_t* tempfname,
	int32_t len,
	std::shared_ptr<NotifyView> notifier)
{
	int32_t total = 0;
	float percent = 0.0;
	int r = -1;
	FILE* fp = f_open_u(tempfname, (wchar_t*)L"wb");
	if (!fp) {
		return RSP_FILE_ERROR;
	}

	try {
		NonBlockingWriteEx(sock, (char*)&r, sizeof(r));

		if (notifier && notifier->function && notifier->hWnd) {
			notifier->function(notifier->hWnd);
		}

		do {
			Buffer b;
			uint32_t rr = 0;
			r = NonBlockingRead(sock, b, NON_BLOCK_TO);
			rr = r;
			if (r > 0) {
				fwrite((void*)b, rr, 1, fp);
				total += r;
				if (notifier && notifier->function && notifier->hWnd) {
					float pcent = ((float)total / (float)(len)) * (float)100.0;
					float diff = pcent - percent;
					if (diff > 1.0) {
#ifndef AUTH_SERVICE
						WCHAR msg[64];
						swprintf_s(msg, 64, L"Percent downloaded: %f of %u bytes\n", pcent, len);
						SetLocalStatus(msg, false);
#endif
						percent = pcent;
						notifier->function(notifier->hWnd);
					}
				}
			}
			else {
				fclose(fp);
				return RSP_SOCKET_IO_ERROR;
			}
		} while (total < len);

#ifndef AUTH_SERVICE
		WCHAR msg[64];
		swprintf_s(msg, 64, L"Total %u of %d downloaded\n", total, len);
		SetLocalStatus(msg, true);
#endif

		fclose(fp);

		DeleteFileW(filename);
		if (!MoveFileW(tempfname, filename)) {
			DeleteFileW(tempfname);
			return RSP_FILE_MOVE_ERROR;
		}

		return RSP_SUCCESS;
	}
	catch (...) {
		fclose(fp);
		return RSP_SOCKET_IO_ERROR;
	}
}

Responses
DocHandler::ProxyReceiveDocument(
	TLSContext& tls,
	SOCKET sbSocket,
	int32_t len,
	WCHAR* pwcLocalName)
{
	int r = -1;
	int32_t total = 0;
	Buffer bHash;
	Buffer bOtherHash;
	FILE* fpLocal = 0;

	try {
		NonBlockingRead(sbSocket, bHash);

		bHash.Clear();
		bHash.Append((char*)"ReiazDean", 9);

		if (pwcLocalName) {
			fpLocal = f_open_u(pwcLocalName, (wchar_t*)L"wb");
		}

		do {
			uint32_t rr = 0;
			Buffer b;
			r = tls.DoNonBlockingReadEx(b);
			if (r < 0) {
				return RSP_SOCKET_IO_ERROR;
			}

			if (fpLocal) {
				fwrite((void*)b, 1, r, fpLocal);
			}

			total += (int32_t)r;
			rr = r;
			if (r > 0) {
				Buffer bIn;
				bIn.Append(bHash);
				bIn.Append((void*)b, rr);
				if (Sha256((uint8_t*)bIn, bIn.Size(), bHash) != SHA256_DIGEST_LENGTH) {
					if (fpLocal) {
						fclose(fpLocal);
						DeleteFileW(pwcLocalName);
					}
					return RSP_DIGEST_ERROR;
				}

				if (r != NonBlockingWriteEx(sbSocket, (char*)b, rr, NON_BLOCK_TO)) {
					if (fpLocal) {
						fclose(fpLocal);
						DeleteFileW(pwcLocalName);
					}
					return RSP_SOCKET_IO_ERROR;
				}
			}
		} while (total < len);

		{
			//signal the sender it may send the hash
			Buffer b((void*)&r, sizeof(r));
			tls.DoNonBlockingWrite(b);
		}

		if (fpLocal) {
			fclose(fpLocal);
			fpLocal = 0;
		}

		r = tls.DoNonBlockingReadEx(bOtherHash, SHA256_DIGEST_LENGTH);
		if (r != SHA256_DIGEST_LENGTH) {
			if (pwcLocalName) {
				DeleteFileW(pwcLocalName);
			}
			return RSP_SOCKET_IO_ERROR;
		}

		if (memcmp((void*)bHash, (void*)bOtherHash, SHA256_DIGEST_LENGTH) != 0) {
			if (pwcLocalName) {
				DeleteFileW(pwcLocalName);
			}
			return RSP_HASH_MISMATCH;
		}

		return RSP_SUCCESS;
	}
	catch (...) {
		if (fpLocal) {
			fclose(fpLocal);
			fpLocal = 0;
		}
		return RSP_SOCKET_IO_ERROR;
	}
}

Responses
DocHandler::ProxySendLocalDocument(
	SOCKET sbSocket,
	WCHAR* pwcLocalName)
{
	uint32_t r = 0;
	uint32_t total = 0;
	Buffer bHash;
	FILE* fpLocal = 0;

	try {
		NonBlockingRead(sbSocket, bHash);

		if (pwcLocalName) {
			fpLocal = f_open_u(pwcLocalName, (wchar_t*)L"rb");
		}

		if (!fpLocal) {
			return RSP_FILE_ERROR;
		}

		do {
			Buffer b(FILE_TRANSFER_CHUNK_SZ);
			r = (uint32_t)fread((void*)b, 1, FILE_TRANSFER_CHUNK_SZ, fpLocal);
			if (r != NonBlockingWriteEx(sbSocket, (char*)b, r, NON_BLOCK_TO)) {
				fclose(fpLocal);
				return RSP_SOCKET_IO_ERROR;
			}
		} while (r == FILE_TRANSFER_CHUNK_SZ);

		fclose(fpLocal);
		fpLocal = 0;

		return RSP_SUCCESS;
	}
	catch (...) {
		if (fpLocal) {
			fclose(fpLocal);
			fpLocal = 0;
		}
		return RSP_FILE_ERROR;
	}
}

bool
DocHandler::getUPN()
{
	try {
		Certificate cert(m_Certificate);
		m_UPN.Clear();
		return cert.GetUPNSubjectAltName(m_UPN);
	}
	catch (...) {
		return false;
	}
}

void
DocHandler::PrintOn(WCHAR* pwcBuf, uint32_t sz) {
	try {
		time_t when;
		char buf_t[64];
		memset(buf_t, 0, sizeof(buf_t));
		if (GetTimeStamp(when)) {
			struct tm tm_buf;
			/* Convert to local time safely on Windows */
			localtime_s(&tm_buf, &when);
			/* Format: YYYY-MM-DD HH:MM:SS */
			strftime(buf_t, sizeof(buf_t), "%Y-%m-%d %H:%M:%S", &tm_buf);
		}
		
		if (pwcBuf && getUPN()) {
			swprintf_s(pwcBuf, sz,
				L"Name = %s\r\n%s\r\n%s\r\n%s\r\nApplication = %s\r\nHsmKeyName = %s\r\nUser = %S\r\nTimeStamp = %S",
				(wchar_t*)m_Name,
				m_Verified ? L"VERIFIED" : L"NOT VERIFIED",
				(wchar_t*)m_Version,
				(wchar_t*)m_Label,
				(wchar_t*)m_Application,
				(wchar_t*)m_HsmKeyName,
				(char*)m_UPN,
				buf_t
				);
		}
	}
	catch (...) {
		return;
	}
}
