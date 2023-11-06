#pragma once

#include "beacon.h"

 #define PRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
 #define PRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#if defined(DEBUG)
 #define DPRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#else
 #define DPRINT(...)
#endif

#if defined(DEBUG)
 #define DPRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#else
 #define DPRINT_ERR(...)
#endif

#define syscall_failed(syscall_name, status) \
    DPRINT_ERR( \
        "Failed to call %s, status: 0x%lx", \
        syscall_name, \
        status \
    )

#define function_failed(function) \
    DPRINT_ERR( \
        "Call to '%s' failed, error: %ld", \
        function, \
        GetLastError() \
    )

#define malloc_failed() function_failed("malloc")

#define api_not_found(function) \
    DPRINT_ERR( \
        "The address of '%s' was not found", \
        function \
    )
