#pragma once
#include "Utils.h"

namespace ReiazDean {
	//*************************************************
	//
	//CLASS RSAPublicKey 
	//
	//*************************************************
	class RSAPublicKey {
		//************   Cons/Destruction   ***********
	private:
	protected:
		RSAPublicKey() {};
	public:
		RSAPublicKey(uint8_t* pbData, size_t cbData);
		RSAPublicKey(const RSAPublicKey&) = delete;
		RSAPublicKey(RSAPublicKey&&) = delete;
		virtual ~RSAPublicKey();

		//************   Class Attributes   ****************
	private:
	protected:
	public:

		//************   Class Methods   *******************
	private:
	protected:
	public:

		//************ Instance Attributes  ****************
	private:
		Buffer m_bPublicKey;
	protected:

		//************ Instance Methods  ****************
	private:
	protected:
	public:
		RSAPublicKey& operator=(const RSAPublicKey& original) = delete;
		RSAPublicKey& operator=(RSAPublicKey&& original) = delete;
		SECURITY_STATUS VerifySignature(VOID* pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags);
		SECURITY_STATUS Encrypt(PBYTE pbInput, DWORD cbInput, Buffer& bEnc);
	};
}
