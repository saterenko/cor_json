#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define LOG_FAIL(_frm) printf("[" KMAG "FAIL  " KNRM "] %s in %s:%d, " _frm "\n", __FUNCTION__, __FILE__, __LINE__);
#define LOG_PFAIL(_frm, _args...) printf("[" KMAG "FAIL  " KNRM "] %s in %s:%d, " _frm "\n", __FUNCTION__, __FILE__, __LINE__, _args);
#define LOG_PASSED printf("[" KGRN "PASSED" KNRM "] %s\n", __FUNCTION__);
#define LOG_PINFO(_fmt, _args...) printf("[" KCYN "INFO  " KNRM "] %s " _fmt "\n", __FUNCTION__, _args);

typedef int (test_myslave_test_handler) ();

#define BEGIN_TEST(_name) static int _name() {
#define BEGIN_TESTA(_function) static int _function {
#define END LOG_PASSED; return 0; }
#define RUN_TEST(_name) \
    if (_name() != 0) { \
        exit(0); \
    }
#define RUN_TESTA(_function) \
    if (_function != 0) { \
        exit(0); \
    }

#define test_int_eq(_p1, _p2) \
    if (((int) _p1) != ((int) _p2)) { \
        LOG_PFAIL(#_p1 " (%d) != " #_p2 " (%d)", (int) _p1, (int) _p2); \
        return -1; \
    }

#define test_int_ne(_p1, _p2) \
    if (((int) _p1) == ((int) _p2)) { \
        LOG_PFAIL(#_p1 " (%d) == " #_p2 " (%d)", (int) _p1, (int) _p2); \
        return -1; \
    }

#define test_uint_eq(_p1, _p2) \
    if (((unsigned int) _p1) != ((unsigned int) _p2)) { \
        LOG_PFAIL(#_p1 " (%u) != " #_p2 " (%u)", (unsigned int) _p1, (unsigned int) _p2); \
        return -1; \
    }

#define test_uint_ne(_p1, _p2) \
    if (((unsigned int) _p1) == ((unsigned int) _p2)) { \
        LOG_PFAIL(#_p1 " (%u) == " #_p2 " (%u)", (unsigned int) _p1, (unsigned int) _p2); \
        return -1; \
    }

#define test_ptr_eq(_p1, _p2) \
    if (((uintptr_t) _p1) != ((uintptr_t) _p2)) { \
        LOG_PFAIL(#_p1 " (%lx) != " #_p2 " (%lx)", (uintptr_t) _p1, (uintptr_t) _p2); \
        return -1; \
    }

#define test_ptr_ne(_p1, _p2) \
    if (((uintptr_t) _p1) == ((uintptr_t) _p2)) { \
        LOG_PFAIL(#_p1 " (%" PRIxPTR ") == " #_p2 " (%" PRIxPTR ")", (uintptr_t) _p1, (uintptr_t) _p2); \
        return -1; \
    }

#define test_str_eq(_p1, _p2) \
    if (strcmp((_p1), (_p2)) != 0) { \
        LOG_PFAIL(#_p1 " (%s) != " #_p2 " (%s)", _p1, _p2); \
        return -1; \
    }

#define test_strn_eq(_p1, _p2, _n) \
    if (strncmp((_p1), (_p2), (_n)) != 0) { \
        LOG_PFAIL(#_p1 " (%.*s) != " #_p2 " (%.*s)", (int) _n, _p1, (int) _n, _p2); \
        return -1; \
    }
