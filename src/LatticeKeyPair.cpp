/*
Copyright(c) 2026 REIAZDEAN CONSULTING INC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at :

http://www.apache.org/licenses/LICENSE-2.0
*/
#include "stdafx.h"
#include "pch.h"
#include "LatticeKeyPair.h"

using namespace ReiazDean;

/******************************************************************************************
Function			ImportPublic
Parameters:			uint8_t* pcPubKey, size_t szPubKey
*******************************************************************************************/
bool LatticeKeyPair::ImportPublic(uint8_t* pcPubKey, size_t szPubKey)
{
    try {
        if (pcPubKey) {
            m_PubKey.Clear();
            m_PubKey.Append((void*)pcPubKey, szPubKey);
            return true;
        }
    }
    catch (...) {
        m_PubKey.Clear();
        return false;
    }
    return false;
}

/******************************************************************************************
Function			Sign
Parameters:			Buffer bData, Buffer& bSignature
*******************************************************************************************/
uint32_t LatticeKeyPair::Sign(const Buffer& bData, Buffer& bSignature)
{
    return 0;
}

/******************************************************************************************
Function			Verify
Parameters:			Buffer bData, Buffer bSignature
*******************************************************************************************/
bool LatticeKeyPair::Verify(const Buffer& bData, const Buffer bSignature)
{
    return false;
}

/******************************************************************************************
Function			WrapRandomAESkey
Parameters:			uint8_t* pcPubKey, int32_t szPubKey
*******************************************************************************************/
int8_t LatticeKeyPair::WrapRandomAESkey(uint8_t* pcPubKey, int32_t szPubKey, Buffer& bWrappedKey)
{
    return 0;
}

/******************************************************************************************
Function			UnwrapAESKey
Parameters:			Buffer bWrappedKey
*******************************************************************************************/
int8_t LatticeKeyPair::UnwrapAESKey(Buffer bWrappedKey)
{
    return 0;
}
