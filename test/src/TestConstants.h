#ifndef TEST_CONSTANTS_H
#define TEST_CONSTANTS_H

#ifndef USE_NETPGP
#define PEP_TEST_KEY_IMPORT_SUCCESS PEP_KEY_IMPORTED
#define PEP_TEST_NO_KEY_IMPORT PEP_NO_KEY_IMPORTED
#else
#define PEP_TEST_KEY_IMPORT_SUCCESS PEP_KEY_IMPORT_STATUS_UNKNOWN
#define PEP_TEST_NO_KEY_IMPORT PEP_KEY_IMPORT_STATUS_UNKNOWN
#endif


#endif