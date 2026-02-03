#pragma once

#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#define              PAD_PKCS           RSA_PKCS1_PADDING
#define              PAD_OAEP           RSA_PKCS1_OAEP_PADDING
#define              PAD_PSS            RSA_PKCS1_PSS_PADDING

//*************************************************
//
//CLASS PublicKeyOssl 
//
//*************************************************
class PublicKeyOssl {
	//************   Cons/Destruction   ***********
private:
protected:
	PublicKeyOssl() {};
public:
	virtual                      ~PublicKeyOssl() {};

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
protected:

	//************ Instance Methods  ****************
private:
protected:
	virtual void                            Create(const uint8_t *pPubBytes, uint32_t szBytes) = 0;
public:
	virtual uint8_t                         VerifySignature(uint8_t* pcHash, uint32_t szHash, uint8_t* pSignature, uint32_t szSig) = 0;
	virtual uint8_t*                        Encrypt(uint8_t* pData, uint32_t szData, uint32_t* pszEnc, int32_t ipad) = 0;
	virtual uint32_t                        GetSize() = 0;
	virtual uint8_t                         GetType() = 0;

};


//*************************************************
//
//CLASS RSAPublicKeyOssl 
//
//*************************************************
class RSAPublicKeyOssl : public PublicKeyOssl {
//************   Cons/Destruction   ***********
private:								
protected:
                                   RSAPublicKeyOssl();
public:
                                   RSAPublicKeyOssl( uint8_t *pPubBytes, uint32_t szBytes);
      virtual                      ~RSAPublicKeyOssl();

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
protected:
	EVP_PKEY                        *m_publicKey;
	uint32_t                        m_dwModulus;
	
	
//************ Instance Methods  ****************
private:
protected:
	virtual void                   Create(const uint8_t *pPubBytes, uint32_t szBytes);
public:
	virtual uint8_t                VerifySignature(uint8_t* pcHash, uint32_t szHash, uint8_t* pSignature, uint32_t szSig);
	virtual uint8_t*               Encrypt(uint8_t* pData, uint32_t szData, uint32_t* pszEnc, int32_t ipad);
	virtual uint32_t               GetSize() {return m_dwModulus; };
	virtual uint8_t                GetType() { return 1; };
	
};

