 // rdc_events.mc 
 // This is the header section.
 // The following are the categories of events.
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_RUNTIME                 0x2
#define FACILITY_STUBS                   0x3
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_ERROR            0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_INFORMATIONAL    0x3


//
// MessageId: COMMUNICATION_CATEGORY
//
// MessageText:
//
// Client Server Communication Events
//
#define COMMUNICATION_CATEGORY           ((WORD)0x00000001L)

//
// MessageId: FILE_ACCESS_CATEGORY
//
// MessageText:
//
// Classified Document Events
//
#define FILE_ACCESS_CATEGORY             ((WORD)0x00000002L)

//
// MessageId: CIPHER_KEY_CATEGORY
//
// MessageText:
//
// Cipher Key Request Events
//
#define CIPHER_KEY_CATEGORY              ((WORD)0x00000003L)

//
// MessageId: LOCAL_SERVICE_CATEGORY
//
// MessageText:
//
// Service Status Events
//
#define LOCAL_SERVICE_CATEGORY           ((WORD)0x00000004L)

//
// MessageId: WINDOWS_SERVICE_CATEGORY
//
// MessageText:
//
// Service Status Events
//
#define WINDOWS_SERVICE_CATEGORY         ((WORD)0x00000005L)

 // The following are the message definitions.
//
// MessageId: MSG_SUCCESS
//
// MessageText:
//
// The operation succeeded. %2.
//
#define MSG_SUCCESS                      ((DWORD)0x00020100L)

//
// MessageId: MSG_FAILED
//
// MessageText:
//
// The operation failed. %2.
//
#define MSG_FAILED                       ((DWORD)0xC0020101L)

//
// MessageId: MSG_DENIED
//
// MessageText:
//
// The operation was denied. %2.
//
#define MSG_DENIED                       ((DWORD)0x80020102L)

//
// MessageId: MSG_GRANTED
//
// MessageText:
//
// The operation was allowed. %2.
//
#define MSG_GRANTED                      ((DWORD)0x40020103L)

 // The following are the parameter strings */
//
// MessageId: QUARTS_UNITS
//
// MessageText:
//
// quarts%0
//
#define QUARTS_UNITS                     ((DWORD)0x00001000L)

//
// MessageId: GALLONS_UNITS
//
// MessageText:
//
// gallons%0
//
#define GALLONS_UNITS                    ((DWORD)0x00001001L)

