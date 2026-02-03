/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "Utils.h"
#include "SequenceReader.h"
#include "NdacConfig.h"
#include "KSPkey.h"

#define DEFBITS 2048
#define DEFPRIMES 2
#define PWD_SZ 32

extern Buffer* pPasswordBuffer;

BOOL
base64Encode(
    uint8_t* pbDataIn,
    size_t dwLenIn,
    Buffer& bPEM);

extern "C" {

    static int progress_cb(EVP_PKEY_CTX* ctx)
    {
        printf(".");
        return 1;
    }

    EVP_PKEY* app_keygen(EVP_PKEY_CTX* ctx)
    {
        EVP_PKEY* res = NULL;
        int r = 0;

        if (!RAND_status()) {
            printf("Warning: generating random key material may take a long time\n"
                "if the system has a poor entropy source\n");
        }
        r = EVP_PKEY_keygen(ctx, &res);
        if (r == 0) {
            openssl_error((char*)"EVP_PKEY_keygen");
            printf("Generating RSA key status = %d\n", r);
        }
        return res;
    }

    EVP_PKEY* getPublicKey(EVP_PKEY* privatekey)
    {
        EVP_PKEY* pubkey = nullptr;
        BIGNUM* e = nullptr;
        BIGNUM* n = nullptr;
        int r = -1;
        int s = -1;
        uint8_t eC[128];
        uint8_t eN[512];

        memset(eC, 0, sizeof(eC));
        memset(eN, 0, sizeof(eN));
        /* get public exponent */
        if (1 != EVP_PKEY_get_bn_param(privatekey, "e", &e)) {
            return nullptr;
        }

        if (1 != EVP_PKEY_get_bn_param(privatekey, "n", &n)) {
            return nullptr;
        }
        
        r = BN_bn2nativepad(e, eC, sizeof(eC));// BN_bn2bin(e, eC);
        s = BN_bn2nativepad(n, eN, sizeof(eN));//BN_bn2bin(n, eN);

        {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
            size_t ss = s;
            size_t rr = r;
            OSSL_PARAM params[] = { OSSL_PARAM_BN("n", &eN, ss), OSSL_PARAM_BN("e", &eC, rr), OSSL_PARAM_END };
            if (ctx && EVP_PKEY_fromdata_init(ctx)) {
                EVP_PKEY_fromdata(ctx, &pubkey, EVP_PKEY_PUBLIC_KEY, params);
                EVP_PKEY_CTX_free(ctx);
            }
        }
#ifdef _DEBUG
        {
            char c[] = "This is a test!";
            int szData = 0;
            Buffer enc;
            EVP_PKEY_CTX* ctx = nullptr;
            RSA_PubKey_Encrypt(pubkey, (uint8_t*)c, (uint32_t)strlen(c), enc);

            ctx = EVP_PKEY_CTX_new(privatekey, 0);
            if (ctx) {
                size_t outlen = 0;
                EVP_PKEY_decrypt_init(ctx);
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
                if (EVP_PKEY_decrypt(ctx, 0, &outlen, (uint8_t*)enc, enc.Size())) {
                    Buffer b(outlen);
                    EVP_PKEY_decrypt(ctx, (uint8_t*)b, &outlen, enc, enc.Size());
                    printf("\nplain = %s\n", (char*)b);
                }
                EVP_PKEY_CTX_free(ctx);
            }
        }
#endif 
        BN_free(e);
        BN_free(n);

        

        return pubkey;
    }

    bool kspEncrypt(Buffer& bPwd)
    {
        Buffer bEncPwd;
        NdacServerConfig& nc = NdacServerConfig::GetInstance();
        Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);

        if (ERROR_SUCCESS == KSPkey::Encrypt((WCHAR*)bKSPw, (WCHAR*)MY_SERVER_KSP_KEY_NAME, bPwd, bEncPwd)) {
            Buffer bFile = nc.GetValue(TLS_PRIV_KEY_PWD_FILE);
            if (saveToFile((int8_t*)bFile, (int8_t*)bEncPwd, bEncPwd.Size()) == 1) {
                return true;
            }
        }
            
        return false;
    }

    bool createPassword()
    {
        Buffer bRand;
        Buffer bPem;

        RandomBytes(bRand);
        base64Encode((uint8_t*)bRand, bRand.Size(), bPem);
        if (bPem.Size() > 0) {
            pPasswordBuffer->Clear();
            pPasswordBuffer->Append(bPem, min(PWD_SZ, bPem.Size()));
            pPasswordBuffer->NullTerminate();
            //fprintf(stdout, "%s\n", (char*)*pPasswordBuffer);
            return kspEncrypt(*pPasswordBuffer);
        }
        return false;
    }

    EVP_PKEY* genrsa_main(Buffer& bKeyFileName)
    {
        EVP_PKEY* pubkey = nullptr;
        BN_GENCB* cb = BN_GENCB_new();
        ENGINE* eng = NULL;
        BIGNUM* bn = BN_new();
        BIO* out = NULL;
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* ctx = NULL;
        EVP_CIPHER* enc = NULL;
        int ret = 1;
        int num = DEFBITS;
        int primes = DEFPRIMES;
        unsigned long f4 = RSA_F4;
        FILE* fp = NULL;
        double d = sizeof(double);
        double secs = secondsSinceNewyear();

        RAND_add(&secs, sizeof(secs), d);

        if (!createPassword()) {
            printf("\nFAILED to create a secure password!\n");
            return nullptr;
        }

        fp = f_open_f((char*)bKeyFileName, (char*)"wt");
        if (!fp) {
            printf("\nFAILED to open %s for writing private key data!\n", (char*)bKeyFileName);
            return nullptr;
        }
        
        out = BIO_new_fp(fp, BIO_CLOSE | BIO_FP_TEXT);
        if (out == NULL) {
            return nullptr;
        }
       
        secs = secondsSinceNewyear();
        RAND_add(&secs, sizeof(secs), d);

        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx)
            goto end;

        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto end;

        EVP_PKEY_CTX_set_cb(ctx, progress_cb);

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, num) <= 0) {
            printf("Error setting RSA length\n");
            goto end;
        }
        if (!BN_set_word(bn, f4)) {
            printf("Error allocating RSA public exponent\n");
            goto end;
        }
        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) <= 0) {
            printf("Error setting RSA public exponent\n");
            goto end;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) <= 0) {
            printf("Error setting number of primes\n");
            goto end;
        }
        pkey = app_keygen(ctx);
        if (pkey == NULL)
            goto end;

        if (!PEM_write_bio_PrivateKey_traditional(out, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, (char*)*pPasswordBuffer))
            goto end;

        fclose(fp);

        pubkey = getPublicKey(pkey);

        ret = 0;
    end:
        BN_free(bn);
        BN_GENCB_free(cb);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_CIPHER_free(enc);
        BIO_free_all(out);
        
        if (ret != 0)
            printf("\nRSA key generation FAILED.......\n");    

        printf("\n\n");
        
        return pubkey;
    }

}

int
pwd_cb(
    char* buf,
    int size,
    int rwflag,
    void* u)
{
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    Buffer bKSPw = nc.GetValueW(KEY_STORAGE_PROVIDER);
    KSPkey ksp((WCHAR*)bKSPw);
    if (ERROR_SUCCESS == ksp.OpenKey((WCHAR*)MY_SERVER_KSP_KEY_NAME, 0)) {
        Buffer bEnc;
        Buffer bPlain;
        Buffer bFile = nc.GetValue(TLS_PRIV_KEY_PWD_FILE);
        readFile((char*)bFile, bEnc);
        
        if (ERROR_SUCCESS == ksp.Decrypt((uint8_t*)bEnc, bEnc.Size(), bPlain)) {
            bPlain.NullTerminate();
            memset(buf, 0, size);
            strncpy_s(buf, size, (char*)bPlain, bPlain.Size());
            buf[size - 1] = '\0';
            pPasswordBuffer->Clear();
            pPasswordBuffer->Append(bPlain);
            //fprintf(stdout, "%s\n", (char*)*pPasswordBuffer);
        }
    }

    return (int)strlen(buf);
}

EVP_PKEY*
openKey(char* pcPrivKeyFile)
{
    FILE* fp = nullptr;
    EVP_PKEY* privkey = nullptr;
    EVP_PKEY* pubkey = nullptr;
    char pwd[MAX_PASSWD];
    
    fp = f_open_f(pcPrivKeyFile, (char*)"r");
    if (fp) {
        memset(pwd, 0, sizeof(pwd));
        privkey = PEM_read_PrivateKey(fp, 0, pwd_cb, pwd);
        if (privkey) {
            pubkey = getPublicKey(privkey);
            EVP_PKEY_free(privkey);
        }
        else {
            openssl_error((char*)"PEM_read_PrivateKey");
        }
        fclose(fp);
    }
    
    return pubkey;
}

EVP_PKEY*
GenerateOrOpenRSA() {
    Buffer bKeyFileName;
    struct _stat     buf;
    int ret = -1;
    NdacServerConfig& nc = NdacServerConfig::GetInstance();
    
    bKeyFileName = nc.GetValue(TLS_PRIV_KEY_FILE);
    ret = _stat((char*)bKeyFileName, &buf);
    if (ret == 0) {
        printf("\n+++++++++++ABOUT TO OPEN PRIVATE KEY FILE++++++++++++\n");
        return openKey(bKeyFileName);
    }

    printf("\n+++++++++++ABOUT TO GENERATE PRIVATE KEY FILE++++++++++++\n");
    return genrsa_main(bKeyFileName);
}