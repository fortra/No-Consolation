#pragma once

#include <windows.h>

#define NC_HANDLE_INFO_KEY "NoConsolationHandleKey"
#define NC_SAVED_PE_KEY    "NoConsolationSavedPeKey"
#define NC_PE_INFO_KEY     "NoConsolationPeInfoKey"
#define NC_LOADED_DLL_KEY  "NoConsolationLoadedDllKey"
#define NC_MEM_STRUCTS_KEY "NoConsolationMemStructsKey"
#define NC_EXEC_CTX        "NoConsolationExecCtxKey"

#define MIN_XOR_KEY_LENGTH 16

typedef struct _MEMORY_STRUCTS {
    PVOID module_base_address_index;
    PVOID hash_table;
    PVOID ldrp_handle_tls_data;
    PVOID ldrp_release_tls_entry;
    PVOID console_connection_state;
} MEMORY_STRUCTS, * PMEMORY_STRUCTS;

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

typedef struct _LOADED_PE_INFO {
    CHAR         pe_name[MAX_PATH];
    WCHAR        pe_wname[MAX_PATH];
    WCHAR        pe_wpath[MAX_PATH];
    PVOID        pe_base;
    SIZE_T       pe_size;
    BOOL         loaded;
    LPWSTR       cmdwline;
    LPCSTR       cmdline;
    UINT32       timeout;
    BOOL         headers;
    LPSTR        method;
    BOOL         use_unicode;
    BOOL         nooutput;
    BOOL         alloc_console;
    BOOL         load_all_deps;
    LPSTR        load_all_deps_but;
    LPSTR        load_deps;
    LPSTR        search_paths;
    BOOL         custom_loaded;
    BOOL         load_in_progress;
    BOOL         handled_tls;
    //PLIB_LOADED  libs_loaded;
    PVOID        EntryPoint;
    PVOID        DllMain;
    PVOID        DllParam;
    BOOL         is_dll;
    BOOL         is_dependency;
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
    BOOL         dont_unload;
    BOOL         inthread;
} LOADED_PE_INFO, * PLOADED_PE_INFO;

typedef struct _LIBS_LOADED {
    LIST_ENTRY list;
} LIBS_LOADED, * PLIBS_LOADED;

typedef struct _LIB_LOADED {
    LIST_ENTRY list;
    CHAR  name[MAX_PATH];
    PVOID address;
    PLOADED_PE_INFO peinfo;
} LIB_LOADED, * PLIB_LOADED;

typedef struct _EXEC_CTX {
    PVOID Rsp;
    PVOID Rbp;
    PVOID Rip;
    DWORD Tid;
} EXEC_CTX, * PEXEC_CTX;
