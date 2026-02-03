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
#include "Utils.h"
#include "SequenceReader.h"

using namespace ReiazDean;

//*************************************************
//
//CLASS SequenceReader
//
//*************************************************
bool SequenceReaderX::ReadLengthValue(uint8_t *pDER, uint32_t *len, uint32_t *pdwPos)
{
    uint8_t c;
    uint32_t lenOfLen;
    uint32_t i;

    if (!pDER || !len || !pdwPos)
        return false;

    try {
        *pdwPos += 1;
        c = pDER[*pdwPos];

        if ((c & 0x80) != 0x80) //this is "short form length"
            *len = (uint32_t)c;
        else {
            lenOfLen = (uint32_t)(c & 0x7F);
            if ((lenOfLen == 0) || (lenOfLen > 4))
            {
                return false; //we won't deal with constructed lengths or lengths > 4G
            }
            *len = 0;
            for (i = lenOfLen; i > 0; i--) {
                *pdwPos += 1;
                c = pDER[*pdwPos];
                *len += (uint32_t)c * (uint32_t)pow((double)256, (int)(i - 1));
            }
        }
        *pdwPos += 1;
        return true;
    }
    catch (...) {
        return false;
    }
}

bool SequenceReaderX::RemoveTL(Buffer& bDer)
{
    uint32_t    dwLen = 0;
    uint32_t    dwPos = 0;
    Buffer      bTmp = bDer;

    try {
        if (ReadLengthValue((uint8_t*)bTmp, &dwLen, &dwPos)) {
            if ((dwLen + dwPos) == bTmp.Size()) {
                bDer.Clear();
                bDer.Append((uint8_t*)bTmp + dwPos, dwLen);
                return true;
            }
        }
        return false;
    }
    catch (...) {
        bDer.Clear();
        return false;
    }
}

SequenceReaderX::SequenceReaderX()
{
    m_dwLength = 0;
}

SequenceReaderX::~SequenceReaderX()
{
    m_dwLength = 0;
}

bool SequenceReaderX::Initilaize(Buffer bDER)
{
    uint32_t dwPos = 0;

    try {
        if (bDER[0] != 0x30) {
            //LogBinary((uint8_t*)"Bad:\n", (uint8_t*)bDER, bDER.Size());
            return false;
        }

        ReadLengthValue((uint8_t*)bDER, &m_dwLength, &dwPos);
        if ((m_dwLength + dwPos) > bDER.Size()) {
            return false;
        }

        m_bValue.Clear();
        m_bValue.Append((uint8_t*)bDER + dwPos, m_dwLength);

        return true;
    }
    catch (...) {
        m_bValue.Clear();
        return false;
    }
}

bool SequenceReaderX::getElementAt(uint32_t dwIndex, Buffer& bElem)
{
    uint32_t dwPos = 0;
    uint32_t dwOldPos = 0;
    uint32_t dwItemLen;
	size_t   sz = 0;

    try {
        bElem.Clear();

        for (unsigned i = 0; i < dwIndex; i++)
        {
            dwItemLen = 0;
            if (!ReadLengthValue((uint8_t*)m_bValue, &dwItemLen, &dwPos) ||
                (dwPos >= m_dwLength) ||
                ((dwItemLen + dwPos) > m_dwLength))
            {
                return false;
            }

            dwPos += dwItemLen;
        }

        dwItemLen = 0;
        dwOldPos = dwPos;
        if (!ReadLengthValue((uint8_t*)m_bValue, &dwItemLen, &dwPos) ||
            (dwPos >= m_dwLength) ||
            ((dwItemLen + dwPos) > m_dwLength)) {
            return false;
        }
        else {
            sz = (size_t)dwItemLen + (size_t)dwPos - (size_t)dwOldPos;
            bElem.Append((uint8_t*)m_bValue + dwOldPos, sz);
            return true;
        }

        return false;
    }
    catch (...) {
        bElem.Clear();
        return false;
    }
}

bool SequenceReaderX::getValueAt(uint32_t dwIndex, Buffer& bElem)
{
    uint32_t dwPos = 0;
    uint32_t dwItemLen;
    uint8_t* pbTemp = NULL;

    try {
        bElem.Clear();

        for (unsigned i = 0; i < dwIndex; i++)
        {
            dwItemLen = 0;
            if (!ReadLengthValue((uint8_t*)m_bValue, &dwItemLen, &dwPos) ||
                (dwPos >= m_dwLength) ||
                ((dwItemLen + dwPos) > m_dwLength))
            {
                return false;
            }

            dwPos += dwItemLen;
        }

        dwItemLen = 0;
        if (!ReadLengthValue((uint8_t*)m_bValue, &dwItemLen, &dwPos) ||
            (dwPos >= m_dwLength) ||
            ((dwItemLen + dwPos) > m_dwLength)) {
            return false;
        }
        else {
            bElem.Append((uint8_t*)m_bValue + dwPos, dwItemLen);
            return true;
        }

        return false;
    }
    catch (...) {
        bElem.Clear();
        return false;
    }
}

void SequenceReaderX::dump()
{
    Buffer bTemp;
    uint32_t index = 0;

    try {
        while (getElementAt(index, bTemp)) {
            if (bTemp[0] == CONSTRUCTED_SEQUENCE) {
                SequenceReaderX sr;
                sr.Initilaize(bTemp);
                sr.dump();
            }
            else {
                LogBinary(stdout, (uint8_t*)"Element:", (uint8_t*)bTemp, bTemp.Size());
            }
            index++;
        }
    }
    catch (...) {
        return;
    }
}
