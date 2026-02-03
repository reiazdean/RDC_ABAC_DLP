#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    //__checkReturn
    SECURITY_STATUS
        WINAPI
        CreateKyberKey(
            __out uint64_t* handle_p);

    //__checkReturn
    SECURITY_STATUS
        WINAPI
        CreateDilithiumKey(
            __out uint64_t* handle_p);

    SECURITY_STATUS
        WINAPI
        DestroyKey(
            __in uint64_t handle_p);

    //__checkReturn
    SECURITY_STATUS
        WINAPI
        ExportPublicKey(
            __in uint64_t handle,
            __out uint8_t* bPublic,
            __out size_t* szPublic);

    SECURITY_STATUS
        WINAPI
        ImportPublicKey(
            __out uint64_t* handle_p,
            __in uint32_t alg,
            __in uint8_t* bPublic,
            __in size_t szPublic);

    SECURITY_STATUS
        WINAPI
        Sign(
            __in uint64_t handle,
            __in uint8_t* bData,
            __in size_t szData,
            __out uint8_t* pbSig,
            __out size_t* szSig);

    SECURITY_STATUS
        WINAPI
        Verify(
            __in uint64_t handle,
            __in uint8_t* bData,
            __in size_t szData,
            __in uint8_t* bSig,
            __in size_t szSig);

    SECURITY_STATUS
        WINAPI
        Wrap(
            __in uint64_t handle,
            __out uint8_t* bWrapped,
            __out size_t* szWrapped);

    SECURITY_STATUS
        WINAPI
        Unwrap(
            __in uint64_t handle,
            __in uint8_t* bWrapped,
            __in size_t szWrapped);

    SECURITY_STATUS
        WINAPI
        GetSecret(
            __in uint64_t handle,
            __out uint8_t* bSecret,
            __out size_t* szSecret);

    // @@BEGIN_DDKSPLIT

    //typedef __checkReturn SECURITY_STATUS
    typedef SECURITY_STATUS
    (WINAPI* CreateKyberKeyFn)(
        __out uint64_t* handle_p);

    //typedef __checkReturn SECURITY_STATUS
    typedef SECURITY_STATUS
    (WINAPI* CreateDilithiumKeyFn)(
        __out uint64_t* handle_p);

    typedef SECURITY_STATUS
    (WINAPI* DestroyKeyFn)(
        __in uint64_t handle_p);

    //typedef __checkReturn SECURITY_STATUS
    typedef SECURITY_STATUS
    (WINAPI* ExportPublicKeyFn)(
        __in uint64_t handle,
        __out uint8_t* bPublic,
        __out size_t* szPublic);

    typedef SECURITY_STATUS
    (WINAPI* ImportPublicKeyFn)(
        __out uint64_t* handle_p,
        __in uint32_t alg,
        __in uint8_t* bPublic,
        __in size_t szPublic);

    typedef SECURITY_STATUS
    (WINAPI* SignFn)(
        __in uint64_t handle,
        __in uint8_t* bData,
        __in size_t szData,
        __out uint8_t* pbSig,
        __out size_t* szSig);

    typedef SECURITY_STATUS
    (WINAPI* VerifyFn)(
        __in uint64_t handle,
        __in uint8_t* bData,
        __in size_t szData,
        __in uint8_t* bSig,
        __in size_t szSig);

    typedef SECURITY_STATUS
    (WINAPI* WrapFn)(
       __in uint64_t handle,
       __out uint8_t* bWrapped,
       __out size_t* szWrapped);

    typedef SECURITY_STATUS
    (WINAPI* UnwrapFn)(
       __in uint64_t handle,
       __in uint8_t* bWrapped,
       __in size_t szWrapped);

    typedef SECURITY_STATUS
    (WINAPI* GetSecretFn)(
       __in uint64_t handle,
       __out uint8_t* bSecret,
       __out size_t* szSecret);

    // @@END_DDKSPLIT


    // @@BEGIN_DDKSPLIT

    typedef struct _CRYSTALS_FUNCTION_TABLE
    {
        uint64_t                   Version;
        CreateKyberKeyFn           CreateKyberKey;
        CreateDilithiumKeyFn       CreateDilithiumKey;
        DestroyKeyFn               DestroyKey;
        ExportPublicKeyFn          ExportPublicKey;
        ImportPublicKeyFn          ImportPublicKey;
        SignFn                     Sign;
        VerifyFn                   Verify;
        WrapFn                     Wrap;
        UnwrapFn                   Unwrap;
        GetSecretFn                GetSecret;
    } CRYSTALS_FUNCTION_TABLE;

    //__checkReturn
    NTSTATUS
        WINAPI
        GetCrystalsInterface(
            __out  CRYSTALS_FUNCTION_TABLE** ppFunctionTable
        );

    //typedef __checkReturn NTSTATUS
    typedef NTSTATUS
    (WINAPI* GetCrystalsInterfaceFn)(
        __out  CRYSTALS_FUNCTION_TABLE** ppFunctionTable
        );


#ifdef __cplusplus
}       // Balance extern "C" above
#endif
