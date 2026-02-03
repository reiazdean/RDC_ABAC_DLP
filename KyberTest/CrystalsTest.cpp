#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include "Crystals.h"

#define ALG_KYBER 1
#define ALG_DILITHIUM 2

GetCrystalsInterfaceFn GetLibInterface = nullptr;
CRYSTALS_FUNCTION_TABLE* pFunctions = nullptr;

HINSTANCE LibHandle = 0;

void
LogBinary(
    FILE* fp,
    uint8_t* label,
    uint8_t* data,
    uint32_t len)
{
    unsigned long i;

    if (!label || !data || !len)
        return;

    fprintf(fp, "%s\n", label);
    for (i = 1; i < len + 1; i++) {
        fprintf(fp, "%02X ", data[i - 1]);
        if ((i % 16) == 0) fprintf(fp, "\r\n");
    }
    if ((i % 16) != 0) fprintf(fp, "\r\n");
    fprintf(fp, "\n\n");
}


int main() {
    uint64_t hK = 0;
    uint64_t hD = 0;
    uint64_t hKpub = 0;
    uint64_t hDpub = 0;
    NTSTATUS ss = NTE_FAIL;
    LibHandle = LoadLibrary(L"C:\\Users\\web\\repos\\OpenSource\\DLP_Solution\\x64\\Debug\\Crystals.dll");
    if (!LibHandle) {
        printf("FAILED LoadLibrary = %p \n", LibHandle);
        return false;
    }

    GetLibInterface = (GetCrystalsInterfaceFn)GetProcAddress(LibHandle, "GetCrystalsInterface");
    if (!GetLibInterface) {
        printf("FAILED GetProcAddress = %p \n", GetLibInterface);
    }
    else {
        if (ERROR_SUCCESS != GetLibInterface(&pFunctions)) {
            goto done;
        }
    }
    
    if (ERROR_SUCCESS == pFunctions->CreateDilithiumKey(&hD)) {
        size_t sz = 0;
        if (ERROR_SUCCESS == pFunctions->ExportPublicKey(hD, nullptr, &sz)) {
            uint8_t* p = new uint8_t[sz];
            if (ERROR_SUCCESS == pFunctions->ExportPublicKey(hD, p, &sz)) {
                LogBinary(stdout, (uint8_t*)"pk D", p, sz);
                if (ERROR_SUCCESS == pFunctions->ImportPublicKey(&hDpub, ALG_DILITHIUM, p, sz)) {
                    printf("\nsuccess hDpub %u\n", hDpub);
                }
            }
            delete[] p;
        }
    }

    if (ERROR_SUCCESS == pFunctions->CreateKyberKey(&hK)) {
        size_t sz = 0;
        if (ERROR_SUCCESS == pFunctions->ExportPublicKey(hK, nullptr, &sz)) {
            uint8_t* p = new uint8_t[sz];
            if (ERROR_SUCCESS == pFunctions->ExportPublicKey(hK, p, &sz)) {
                LogBinary(stdout, (uint8_t*)"pk K", p, sz);
                if (ERROR_SUCCESS == pFunctions->ImportPublicKey(&hKpub, ALG_KYBER, p, sz)) {
                    printf("\nsuccess hKpub %u\n", hKpub);
                }
            }
            delete[] p;
        }
    }

    {
        uint8_t test[256];
        uint8_t sig[4096];
        size_t sz = 0;
        
        memset(test, 'a', sizeof(test));
        if (ERROR_INSUFFICIENT_BUFFER == pFunctions->Sign(hD, test, sizeof(test), sig, &sz)) {
            if (ERROR_SUCCESS == pFunctions->Sign(hD, test, sizeof(test), sig, &sz)) {
                if (ERROR_SUCCESS == pFunctions->Verify(hDpub, test, sizeof(test), sig, sz)) {
                    printf("\nsuccess signnature VERIFIES %zu\n", sz);
                }
            }
        }
    }

    {
        uint8_t wrapped[4096];
        size_t szW = 4096;
        if (ERROR_SUCCESS == pFunctions->Wrap(hKpub, wrapped, &szW)) {
            uint8_t sec1[256];
            size_t szS1 = 256;
            if (ERROR_SUCCESS == pFunctions->GetSecret(hKpub, sec1, &szS1)) {
                LogBinary(stdout, (uint8_t*)"Sec1", sec1, szS1);
            }
            if (ERROR_SUCCESS == pFunctions->Unwrap(hK, wrapped, szW)) {
                uint8_t sec2[256];
                size_t szS2 = 256;
                if (ERROR_SUCCESS == pFunctions->GetSecret(hK, sec2, &szS2)) {
                    LogBinary(stdout, (uint8_t*)"Sec2", sec2, szS2);
                }
            }
        }
    }
 

    if (hD) {
        pFunctions->DestroyKey(hD);
    }

    if (hK) {
        pFunctions->DestroyKey(hK);
    }

done:

    FreeLibrary(LibHandle);

    return 0;
}
