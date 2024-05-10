#pragma once

#include <windows.h>

#define MIN_XOR_KEY_LENGTH 16

typedef struct _SAVED_PE {
    CHAR    pe_name[MAX_PATH];
    PBYTE   pe_base;
    SIZE_T  pe_size;
    PBYTE   xor_key;
    ULONG32 xor_length;
    BOOL    encrypted;
    CHAR    username[MAX_PATH];
    CHAR    loadtime[MAX_PATH];
    struct _SAVED_PE* next;
} SAVED_PE, * PSAVED_PE;

typedef struct _HANDLE_INFO {
    HANDLE hWrite;
    HANDLE hRead;
    int fo_msvc;
    int fo_ucrtbase;
} HANDLE_INFO, * PHANDLE_INFO;

typedef struct _LIB_LOADED {
    CHAR  name[MAX_PATH];
    PVOID address;
    struct _LIB_LOADED* next;
} LIB_LOADED, * PLIB_LOADED;

typedef struct _LOADED_PE_INFO {
    PVOID        pe_base;
    SIZE_T       pe_size;
    LPWSTR       cmdwline;
    LPCSTR       cmdline;
    UINT32       timeout;
    BOOL         headers;
    LPSTR        method;
    BOOL         use_unicode;
    BOOL         nooutput;
    BOOL         alloc_console;
    BOOL         unload_libs;
    PLIB_LOADED  libs_loaded;
    PVOID        EntryPoint;
    PVOID        DllMain;
    PVOID        DllParam;
    BOOL         is_dll;
    BOOL         loaded_msvcrt;
    BOOL         loaded_mscoree;
    BOOL         loaded_ucrtbase;
    HANDLE       hSection;
    HANDLE       hThread;
    PHANDLE_INFO Handles;
    HANDLE       hHwBp1;
    HANDLE       hHwBp2;
    BOOL         modified_msvc_stdout;
    BOOL         modified_msvc_stderr;
    BOOL         modified_ucrtbase_stdout;
    BOOL         modified_ucrtbase_stderr;
    BOOL         modified_user_params_stdout;
    BOOL         modified_user_params_stderr;
    BOOL         modified_console_reference;
    BOOL         modified_console_handle;
    HANDLE       original_user_params_stdout;
    HANDLE       original_user_params_stderr;
    HANDLE       original_console_reference;
    PVOID        console_reference_addr;
    PVOID        msvc_stdout;
    PVOID        msvc_stderr;
    PVOID        original_msvc_stdout;
    PVOID        original_msvc_stderr;
    PVOID        ucrtbase_stdout;
    PVOID        ucrtbase_stderr;
    PVOID        original_ucrtbase_stdout;
    PVOID        original_ucrtbase_stderr;
    HANDLE       original_console_handle;
    PVOID        func_table;
    BOOL         link_to_peb;
    BOOL         linked;
    PVOID        ldr_entry;
} LOADED_PE_INFO, * PLOADED_PE_INFO;

