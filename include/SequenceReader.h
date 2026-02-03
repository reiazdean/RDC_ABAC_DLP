#pragma once
#ifdef OS_WIN32
#include <Windows.h>
#endif
#include <stdint.h>
#include "Buffer.h"

#define		UNIVERSAL_CLASS				0x0
#define		APPLICATION_CLASS			0x40
#define		CONTEXT_CLASS				0x80
#define		PRIVATE_CLASS				0xC0

#define		PRIMATIVE_TYPE				0x0
#define		CONSTRUCTED_TYPE			0x20
#define		CONSTRUCTED_SEQUENCE		0x30
#define		CONSTRUCTED_SET				0x31

#define		UNIVERSAL_TYPE_BOOL			0x01
#define		UNIVERSAL_TYPE_INT			0x02
#define		UNIVERSAL_TYPE_BITSTR		0x03
#define		UNIVERSAL_TYPE_OCTETSTR		0x04
#define		UNIVERSAL_TYPE_NULL			0x05
#define		UNIVERSAL_TYPE_OID			0x06
#define		UNIVERSAL_TYPE_REAL			0x09
#define		UNIVERSAL_TYPE_ENUM			0x0A
#define		UNIVERSAL_TYPE_UTF8STRING	0x0C		//multi uint8_t string
#define		UNIVERSAL_TYPE_SEQUENCE		0x10
#define		UNIVERSAL_TYPE_SET			0x11
#define		UNIVERSAL_TYPE_STRING0		0x12
#define		UNIVERSAL_TYPE_STRING1		0x13
#define		UNIVERSAL_TYPE_STRING2		0x14
#define		UNIVERSAL_TYPE_STRING3		0x15
#define		UNIVERSAL_TYPE_STRING4		0x16
#define		UNIVERSAL_TYPE_DATE1		0x17
#define		UNIVERSAL_TYPE_DATE2		0x18
#define		UNIVERSAL_TYPE_STRING5		0x19
#define		UNIVERSAL_TYPE_STRING6		0x1A
#define		UNIVERSAL_TYPE_STRING7		0x1B
#define		UNIVERSAL_TYPE_STRING8		0x1C
#define		UNIVERSAL_TYPE_STRING9		0x1D
#define		UNIVERSAL_TYPE_STRING10		0x1E       //utf16


using std::mutex;
using std::string;
using std::unique_ptr;

namespace ReiazDean {
    //*************************************************
    //
    //CLASS SequenceReader
    //
    //*************************************************
    class SequenceReaderX {
        //************   Cons/Destruction   ***********
    protected:
    public:
        SequenceReaderX();
        SequenceReaderX(const SequenceReaderX&) = delete;
        SequenceReaderX(SequenceReaderX&&) = delete;
        ~SequenceReaderX();

    private:
    protected:
    public:
        static bool                     ReadLengthValue(uint8_t* pDER, uint32_t* len, uint32_t* pdwPos);
        static bool                     RemoveTL(Buffer& bDer);

        //************ Instance Attributes  ****************
    private:
        uint32_t                        m_dwLength;
        Buffer                          m_bValue;

        //************ Instance Methods  ****************
    private:
    public:
        SequenceReaderX&                operator=(const SequenceReaderX& original) = delete;
        SequenceReaderX&                operator=(SequenceReaderX&& original) = delete;
        bool                            Initilaize(Buffer bDER);
        bool                            getElementAt(uint32_t dwIndex, Buffer& bElem);
        bool                            getValueAt(uint32_t dwIndex, Buffer& bElem);
        void                            dump();

    };
}

