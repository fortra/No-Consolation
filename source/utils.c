#include "utils.h"

#ifdef _WIN64

// TODO: implement ntdll!LdrpHandleTlsData
PVOID find_ldrp_handle_tls_data(VOID)
{
    PIMAGE_NT_HEADERS      nt             = NULL;
    PIMAGE_DOS_HEADER      dos            = NULL;
    DWORD                  rva            = 0;
    DWORD                  size           = 0;
    PRUNTIME_FUNCTION      func_table     = NULL;
    PRUNTIME_FUNCTION      func_entry     = NULL;
    PVOID                  func_addr      = NULL;
    DWORD                  func_size      = 0;
    PBYTE                  bytes_to_match = (PBYTE)"\xba\x23\x00\x00\x00\x48\x83\xc9\xff\xe8";
    PVOID                  address        = NULL;
    PVOID                  rip            = NULL;
    PVOID                  nt_set         = NULL;
    DWORD                  offset         = 0;
    PMEMORY_STRUCTS        mem_structs    = NULL;

    /*
     * We parse the export directory to get a reference to all non-leaf functions in ntdll.
     * For each one, we check if we find a call to NtSetInformationProcess with
     * PROCESS_INFORMATION_CLASS set to ProcessTlsInformation (0x23)
     */

    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->ldrp_handle_tls_data)
        return mem_structs->ldrp_handle_tls_data;

    dos    = xGetLibAddress("ntdll", TRUE, NULL);
    nt     = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);
    nt_set = xGetProcAddress(dos, "NtSetInformationProcess", 0);
    if (!nt_set)
    {
        api_not_found("NtSetInformationProcess");
        return NULL;
    }

    rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);
    func_table = RVA2VA(PRUNTIME_FUNCTION, dos, rva);
    // iterate over each non-leaf functions in ntdll
    for (DWORD i = 0; i < size; ++i)
    {
        func_entry = RVA2VA(PRUNTIME_FUNCTION, func_table, (sizeof(RUNTIME_FUNCTION) * i));
        func_addr  = RVA2VA(PVOID, dos, func_entry->BeginAddress);
        func_size  = func_entry->EndAddress - func_entry->BeginAddress;
        // search for the byte pattern on this function
        if (find_pattern(func_addr, func_size, bytes_to_match, "xxxxxxxxxx", &address))
        {
            /*
             * We found a function call with the parameters -1 and 0x28, lets confirm
             * the function being called is indeed NtSetInformationProcess
             */

            rip     = RVA2VA(PVOID, address, 10 + sizeof(DWORD));
            offset  = (ULONG_PTR)nt_set - (ULONG_PTR)rip;
            address = RVA2VA(PVOID, address, 10);
            if (*(PDWORD)address == offset)
            {
                // if the offset matches, then the function being call is NtSetInformationProcess

                // save the address of the ldrp_handle_tls_data;
                if (mem_structs)
                    mem_structs->ldrp_handle_tls_data = func_addr;

                return func_addr;
            }
        }
    }

    api_not_found("LdrpHandleTlsData");

    return NULL;
}

// TODO: implement ntdll!LdrpReleaseTlsEntry
PVOID find_ldrp_release_tls_entry(VOID)
{
    PIMAGE_NT_HEADERS      nt             = NULL;
    PIMAGE_DOS_HEADER      dos            = NULL;
    DWORD                  rva            = 0;
    DWORD                  size           = 0;
    PRUNTIME_FUNCTION      func_table     = NULL;
    PRUNTIME_FUNCTION      func_entry     = NULL;
    PVOID                  func_addr      = NULL;
    DWORD                  func_size      = 0;
    PBYTE                  bytes_to_match = (PBYTE)"\x0f\xb3\x01";
    PVOID                  address        = NULL;
    PMEMORY_STRUCTS        mem_structs    = NULL;

    /*
     * We parse the export directory to get a reference to all non-leaf functions in ntdll.
     * For each one, we check if we find the pattern matching
     */

    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->ldrp_release_tls_entry)
        return mem_structs->ldrp_release_tls_entry;

    dos    = xGetLibAddress("ntdll", TRUE, NULL);
    nt     = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);

    rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);
    func_table = RVA2VA(PRUNTIME_FUNCTION, dos, rva);
    // iterate over each non-leaf functions in ntdll
    for (DWORD i = 0; i < size; ++i)
    {
        func_entry = RVA2VA(PRUNTIME_FUNCTION, func_table, (sizeof(RUNTIME_FUNCTION) * i));
        func_addr  = RVA2VA(PVOID, dos, func_entry->BeginAddress);
        func_size  = func_entry->EndAddress - func_entry->BeginAddress;
        // search for the byte pattern on this function
        if (find_pattern(func_addr, func_size, bytes_to_match, "xxx", &address))
        {
            // save the address of the ldrp_release_tls_entry;
            if (mem_structs)
                mem_structs->ldrp_release_tls_entry = func_addr;

            return func_addr;
        }
    }

    api_not_found("LdrpReleaseTlsEntry");

    return NULL;
}

#else // _WIN64

PVOID find_ldrp_handle_tls_data(VOID)
{
    PIMAGE_NT_HEADERS      nt          = NULL;
    PIMAGE_DOS_HEADER      dos         = NULL;
    PIMAGE_SECTION_HEADER  pSection    = NULL;
    PBYTE                  nt_set_call = (PBYTE)"\x6a\x23\x6a\xff\xe8";
    PBYTE                  func_start  = (PBYTE)"\x6a\x00\x68";
    PVOID                  address     = NULL;
    PVOID                  start       = NULL;
    PVOID                  rip         = NULL;
    PVOID                  nt_set      = NULL;
    DWORD                  offset      = 0;
    PVOID                  stBegin     = NULL;
    PVOID                  stEnd       = NULL;
    DWORD                  dwLen       = 0;
    PMEMORY_STRUCTS        mem_structs = NULL;

    // on x86, there is no export directory, so we search the entire .text section

    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->ldrp_handle_tls_data)
        return mem_structs->ldrp_handle_tls_data;

    dos    = xGetLibAddress("ntdll", TRUE, NULL);
    nt     = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);
    nt_set = xGetProcAddress(dos, "NtSetInformationProcess", 0);
    if (!nt_set)
    {
        api_not_found("NtSetInformationProcess");
        return NULL;
    }

    // find the .text section
    pSection = IMAGE_FIRST_SECTION(nt);
    for (INT i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!strncmp(".text", (LPCSTR)pSection->Name, 8))
        {
            stBegin = RVA2VA(PVOID, dos, pSection->VirtualAddress);
            dwLen = pSection->Misc.VirtualSize;
            break;
        }

        ++pSection;
    }

    if (!stBegin || !dwLen)
    {
        DPRINT("Failed to find section");
        return NULL;
    }

    stEnd = RVA2VA(PVOID, stBegin, dwLen);

    while ((ULONG_PTR)stBegin + 5 < (ULONG_PTR)stEnd)
    {
        dwLen = (ULONG_PTR)stEnd - (ULONG_PTR)stBegin;
        if (find_pattern(stBegin, dwLen, nt_set_call, "xxxxx", &address))
        {
            /*
             * We found a function call with the parameters -1 and 0x28, lets confirm
             * the function being called is indeed NtSetInformationProcess
             */

            rip     = RVA2VA(PVOID, address, 5 + sizeof(DWORD));
            offset  = (ULONG_PTR)nt_set - (ULONG_PTR)rip;
            address = RVA2VA(PVOID, address, 5);
            if (*(PDWORD)address == offset)
            {
                /*
                 * If the offset matches, then the function being call is NtSetInformationProcess,
                 * but on x86, we still need to find the start of the function, we use another
                 * pattern match for that
                 */

                for (int i = 0; i < 0x300; ++i)
                {
                    start = RVA2VA(PVOID, address, - i);
                    if (find_pattern(start, 3, func_start, "x?x", NULL))
                    {
                        // save the address of the ldrp_handle_tls_data;
                        if (mem_structs)
                            mem_structs->ldrp_handle_tls_data = start;

                        return start;
                    }
                }
            }

            stBegin = address;
        }
        else
        {
            break;
        }
    }

    api_not_found("LdrpHandleTlsData")

    return NULL;
}

PVOID find_ldrp_release_tls_entry(VOID)
{
    PIMAGE_NT_HEADERS      nt          = NULL;
    PIMAGE_DOS_HEADER      dos         = NULL;
    PIMAGE_SECTION_HEADER  pSection    = NULL;
    PBYTE                  peb_bytes   = (PBYTE)"\x64\xa1\x30\x00\x00\x00\x56\x57\xff\x70\x18";
    PBYTE                  func_start  = (PBYTE)"\x8b\xff";
    PVOID                  address     = NULL;
    PVOID                  start       = NULL;
    PVOID                  stBegin     = NULL;
    PVOID                  stEnd       = NULL;
    DWORD                  dwLen       = 0;
    PMEMORY_STRUCTS        mem_structs = NULL;

    // on x86, there is no export directory, so we search the entire .text section

    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->ldrp_release_tls_entry)
        return mem_structs->ldrp_release_tls_entry;

    dos    = xGetLibAddress("ntdll", TRUE, NULL);
    nt     = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);

    // find the .text section
    pSection = IMAGE_FIRST_SECTION(nt);
    for (INT i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!strncmp(".text", (LPCSTR)pSection->Name, 8))
        {
            stBegin = RVA2VA(PVOID, dos, pSection->VirtualAddress);
            dwLen = pSection->Misc.VirtualSize;
            break;
        }

        ++pSection;
    }

    if (!stBegin || !dwLen)
    {
        DPRINT("Failed to find section");
        return NULL;
    }

    stEnd = RVA2VA(PVOID, stBegin, dwLen);

    while ((ULONG_PTR)stBegin + 11 < (ULONG_PTR)stEnd)
    {
        dwLen = (ULONG_PTR)stEnd - (ULONG_PTR)stBegin;
        if (find_pattern(stBegin, dwLen, peb_bytes, "xxxxxxxxxxx", &address))
        {
            for (int i = 0; i < 0x100; ++i)
            {
                start = RVA2VA(PVOID, address, - i);
                if (find_pattern(start, 2, func_start, "xx", NULL))
                {
                    // save the address of the ldrp_release_tls_entry;
                    if (mem_structs)
                        mem_structs->ldrp_release_tls_entry = start;

                    return start;
                }
            }

            stBegin = address;
        }
        else
        {
            break;
        }
    }

    api_not_found("LdrpReleaseTlsEntry")

    return NULL;
}

#endif

VOID insert_tail_list(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

VOID unlink_from_list(
    PLIST_ENTRY Entry)
{
    Entry->Flink->Blink = Entry->Blink;
    Entry->Blink->Flink = Entry->Flink;
}

SIZE_T StringLengthA(
    IN LPCSTR String)
{
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PCHAR StringConcatA(
    IN PCHAR String,
    IN PCHAR String2)
{
    StringCopyA( &String[ StringLengthA( String ) ], String2 );

    return String;
}

VOID myRtlInitUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString)
{
    SIZE_T Length;

    DestinationString->MaximumLength = 0;
    DestinationString->Length = 0;
    DestinationString->Buffer = (PWCH)SourceString;

    if (ARGUMENT_PRESENT(SourceString)) {
        Length = StringLengthW(SourceString) * sizeof(WCHAR);
        if (Length >= MAX_USTRING) {
            Length = MAX_USTRING - sizeof(UNICODE_NULL);
        }

        DestinationString->Length = (USHORT)Length;
        DestinationString->MaximumLength = (USHORT)(Length + sizeof(UNICODE_NULL));
    }
}

SIZE_T StringLengthW(
    IN LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PCHAR StringCopyA(
    IN PCHAR String1,
    IN PCHAR String2)
{
    PCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}

SIZE_T WCharStringToCharString(
    IN PCHAR Destination,
    IN PWCHAR Source,
    IN SIZE_T MaximumAllowed)
{
    INT Length = MaximumAllowed;

    if (!MaximumAllowed)
        return 0;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SIZE_T CharStringToWCharString(
    IN PWCHAR Destination,
    IN PCHAR Source,
    IN SIZE_T MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if ( ! ( *Destination++ = *Source++ ) )
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

LONG RtlCompareUnicodeString(
    IN PCUNICODE_STRING String1,
    IN PCUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive)
{
    return RtlCompareUnicodeStrings(String1->Buffer, String1->Length,
                                    String2->Buffer, String2->Length,
                                    CaseInSensitive);
}

VOID RtlInitEmptyUnicodeString(
    OUT PUNICODE_STRING UnicodeString,
    IN PWCHAR Buffer,
    IN UINT16 BufferSize)
{
    memset(UnicodeString, 0, sizeof(*UnicodeString));
    UnicodeString->MaximumLength = BufferSize;
    UnicodeString->Buffer = Buffer;
}

LONG RtlCompareUnicodeStrings(
    IN CONST WCHAR* String1,
    IN SIZE_T Length1,
    IN CONST WCHAR* String2,
    IN SIZE_T Length2,
    IN BOOLEAN CaseInSensitive)
{
    CONST WCHAR* s1, * s2, * Limit;
    LONG n1, n2;
    UINT32 c1, c2;

    if (Length1 > LONG_MAX || Length2 > LONG_MAX) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    s1 = String1;
    s2 = String2;
    n1 = (LONG)Length1;
    n2 = (LONG)Length2;

    Limit = (WCHAR*)((CHAR*)s1 + (n1 <= n2 ? n1 : n2));
    if (CaseInSensitive) {
        while (s1 < Limit) {
            c1 = *s1;
            c2 = *s2;
            if (c1 != c2) {

                //
                // Note that this needs to reference the translation table!
                //
                c1 = RTL_UPCASE(c1);
                c2 = RTL_UPCASE(c2);
                if (c1 != c2) {
                    return (INT32)(c1)-(INT32)(c2);
                }
            }
            s1 += 1;
            s2 += 1;
        }

    } else {

        while (s1 < Limit) {
            c1 = *s1;
            c2 = *s2;
            if (c1 != c2) {
                return (LONG)(c1)-(LONG)(c2);
            }
            s1 += 1;
            s2 += 1;
        }
    }

    return n1 - n2;
}

BOOL string_is_included(
    IN PCHAR list_of_strings,
    IN PCHAR string_to_search)
{
    CHAR  some_string[256] = { 0 };
    INT   i                = 0;

    for (;;)
    {
        // store string until null byte, semi-colon or comma encountered
        for (i = 0; list_of_strings[i] != '\0' &&
                    list_of_strings[i] != ';' &&
                    list_of_strings[i] != ',' && i < 256; i++) some_string[i] = list_of_strings[i];
        // nothing stored? end
        if (i == 0) break;
        // skip name plus one for separator
        list_of_strings += (i + 1);
        // store null terminator
        some_string[i] = '\0';
        // if equal, return TRUE
        if (!_stricmp(some_string, string_to_search)) return TRUE;
    }
    return FALSE;
}

BOOL compare_bytes(
    IN PBYTE pData,
    IN PBYTE bMask,
    IN PCHAR szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    }

    return TRUE;
}

BOOL find_pattern(
    IN PVOID dwAddress,
    IN ULONG32 dwLen,
    IN PBYTE bMask,
    IN PCHAR szMask,
    OUT PVOID* pattern_addr)
{
    PVOID current_address = NULL;
    for (ULONG32 i = 0; i < dwLen; i++)
    {
        current_address = RVA2VA(PVOID, dwAddress, i);
        if (compare_bytes(current_address, bMask, szMask))
        {
            if (pattern_addr)
                *pattern_addr = current_address;
            return TRUE;
        }
    }

    return FALSE;
}

// check if bytes are from a windows PE
BOOL is_pe(
    IN HMODULE hLibrary)
{
    PIMAGE_DOS_HEADER dos = NULL;
    PIMAGE_NT_HEADERS nt  = NULL;

    if (!hLibrary)
        return FALSE;

    dos = (PIMAGE_DOS_HEADER)hLibrary;

    // check the MZ magic bytes
    if (dos->e_magic != 0x5A4D)
        return FALSE;

    nt = RVA2VA(PIMAGE_NT_HEADERS, hLibrary, dos->e_lfanew);

    // check the NT_HEADER signature
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    return TRUE;
}

// check if bytes are from a windows DLL
BOOL is_dll(
    IN HMODULE hLibrary)
{
    PIMAGE_DOS_HEADER dos             = NULL;
    PIMAGE_NT_HEADERS nt              = NULL;
    USHORT            Characteristics = 0;

    if (!is_pe(hLibrary))
        return FALSE;

    dos = (PIMAGE_DOS_HEADER)hLibrary;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, hLibrary, dos->e_lfanew);

    // check that it is a DLL and not an EXE
    Characteristics = nt->FileHeader.Characteristics;
    if ((Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
        return FALSE;

    return TRUE;
}

// remember we loaded this DLL by adding it to the 'libs_loaded' linked list
VOID store_loaded_dll(
    IN PLOADED_PE_INFO peinfo,
    IN HMODULE dll,
    IN PCHAR name)
{
    PLIBS_LOADED libs_loaded = NULL;
    PLIB_LOADED  lib_loaded = NULL;

    if (!peinfo)
        return;

    // first, check we didn't include this lib already
    libs_loaded = BeaconGetValue(NC_LOADED_DLL_KEY);
    lib_loaded = (PLIB_LOADED)libs_loaded->list.Flink;
    while (&lib_loaded->list != &libs_loaded->list)
    {
        if (!_stricmp(lib_loaded->peinfo->pe_name, name))
            return;

        lib_loaded = (PLIB_LOADED)lib_loaded->list.Flink;
    }

    // add this DLL to the linked list
    lib_loaded = intAlloc((sizeof(LIB_LOADED)));
    if (!lib_loaded)
        return;
    StringCopyA(lib_loaded->name, name);
    lib_loaded->address = dll;
    lib_loaded->peinfo  = peinfo;

    insert_tail_list(&libs_loaded->list, &lib_loaded->list);
}

/*
 * Some PEs will search for APIs at runtime
 * we need to spoof these as well if we want to prevent
 * our process from exiting.
 * PsExec searches for mscoree!CorExitProcess and calls it if found.
 * This only happens if the CLR is loaded (i.e. PowerShell has been run)
 */
FARPROC WINAPI my_get_proc_address(
    IN HMODULE hModule,
    IN LPSTR lpProcName)
{
    return handle_import(NULL, hModule, NULL, lpProcName);
}

/*
 * If the PE calls GetModuleHandleW(NULL), we need to return
 * the base of our module, instead of the base of the host process
 */
HMODULE WINAPI my_get_module_handle_w(
  IN LPCWSTR lpModuleName)
{
    PLOADED_PE_INFO peinfo = NULL;

    if (!lpModuleName)
    {
        peinfo = BeaconGetValue(NC_PE_INFO_KEY);
        if (peinfo)
        {
            DPRINT("GetModuleHandleW(NULL) was called, returning 0x%p", peinfo->pe_base);
            return peinfo->pe_base;
        }
    }

    // call the original GetModuleHandleW
    HMODULE ( WINAPI *GetModuleHandleW ) ( LPCWSTR ) = xGetProcAddress(xGetLibAddress("kernelbase", TRUE, NULL), "GetModuleHandleW", 0);
    if (GetModuleHandleW)
    {
        return GetModuleHandleW(lpModuleName);
    }
    else
    {
        api_not_found("GetModuleHandleW");
        return NULL;
    }
}

HANDLE get_console_handle(VOID)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    return ProcessParameters->ConsoleHandle;
}

VOID set_console_handle(
    IN HANDLE hConsoleHandle)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    ProcessParameters->ConsoleHandle = hConsoleHandle;
}

HANDLE get_std_out_handle(VOID)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    return ProcessParameters->StandardOutput;
}

VOID set_std_out_handle(
    IN HANDLE hStdOutErr)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    ProcessParameters->StandardOutput = hStdOutErr;
}

HANDLE get_std_err_handle(VOID)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    return ProcessParameters->StandardError;
}

VOID set_std_err_handle(
    IN HANDLE hStdOutErr)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    ProcessParameters->StandardError = hStdOutErr;
}

HANDLE get_std_in_handle(VOID)
{
    uPRTL_USER_PROCESS_PARAMETERS ProcessParameters = (uPRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
    return ProcessParameters->StandardInput;
}

DWORD get_tid(VOID)
{
    return (DWORD)(ULONG_PTR)((PTEB2)NtCurrentTeb())->ClientId.UniqueThread;
}

VOID rtl_exit_user_thread(VOID)
{
    PEXEC_CTX exec_ctx = BeaconGetValue(NC_EXEC_CTX);

    // do we have a execution context saved?
    if (exec_ctx)
    {
        // ensure this is the main thread
        if (exec_ctx->Tid == get_tid())
        {
            // PE has exited, restore the execution context
#ifdef _WIN64
            __asm__(
                "mov rsp, rax \n"
                "mov rbp, rdx \n"
                "jmp rcx \n"
                : // no outputs
                : "r" (exec_ctx->Rsp), // RAX IN
                  "r" (exec_ctx->Rbp), // RDX IN
                  "r" (exec_ctx->Rip)  // RCX IN
            );
#else
            __asm__(
                "mov esp, eax \n"
                "mov ebp, edx \n"
                "jmp ecx \n"
                : // no outputs
                : "r" (exec_ctx->Rsp), // EAX IN
                  "r" (exec_ctx->Rbp), // EDX IN
                  "r" (exec_ctx->Rip)  // ECX IN
            );
#endif
        }
    }

    // either there is no execution context saved or this is not the main thread, simply exit
    VOID ( WINAPI *RtlExitUserThread ) ( NTSTATUS ) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlExitUserThread", 0);
    if (RtlExitUserThread)
    {
        return RtlExitUserThread(0);
    }
    else
    {
        api_not_found("RtlExitUserThread");
    }
}

BOOL create_thread(
    OUT PHANDLE hThread)
{
    time_t   t             = { 0 };
    UINT32   ordinal       = 0;
    PVOID    start_address = NULL;
    NTSTATUS status        = STATUS_UNSUCCESSFUL;

    if (!hThread)
        return FALSE;

    VOID (WINAPI *srand) (int) = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "srand", 0);
    int (WINAPI *rand) (void)  = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "rand", 0);

    if (!srand)
    {
        api_not_found("srand");
        return FALSE;
    }

    if (!rand)
    {
        api_not_found("rand");
        return FALSE;
    }

    time_t (WINAPI* time) (time_t*) = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "time", 0);

    if (!time)
    {
        api_not_found("time");
        return FALSE;
    }

    srand((unsigned) time(&t));

    // obtain a "valid" start address by getting a random Kernel32 API address
    while (!start_address)
    {
        ordinal = rand() & (256 - 1);
        start_address = xGetProcAddress(xGetLibAddress("kernel32", TRUE, NULL), NULL, ordinal);
    }

    status = NtCreateThreadEx(hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), start_address, NULL, 1, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateThreadEx", status);
        return FALSE;
    }

    DPRINT("Created thread with 0x%p as start address", start_address);

    return TRUE;
}

BOOL read_local_pe(
    IN LPCTSTR path,
    OUT PVOID* data,
    OUT int* pelen)
{
    BOOL          ret_val    = FALSE;
    HANDLE        hFile      = NULL;
    DWORD         bRead      = 0;
    LARGE_INTEGER lpFileSize = { 0 };
    PBYTE         pe         = NULL;

    // Try and open a handle to the specified file
    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        PRINT_ERR("Unable to open %s. Last error: %d", path, GetLastError());
        goto Cleanup;
    }

    // Get size of file
    if(!GetFileSizeEx(hFile, &lpFileSize))
    {
        function_failed("GetFileSizeEx");
        goto Cleanup;
    }

    // Allocate buffer to hold the PE
    pe = intAlloc(lpFileSize.LowPart + 1);
    if (!pe)
    {
        malloc_failed();
        goto Cleanup;
    }

    // Read file into buffer
    if(!ReadFile(hFile, pe, lpFileSize.LowPart, &bRead, NULL))
    {
        function_failed("ReadFile");
        goto Cleanup;
    }

    *data  = pe;
    *pelen = lpFileSize.LowPart;

    ret_val = TRUE;

Cleanup:
    if (hFile && hFile != INVALID_HANDLE_VALUE)
        NtClose(hFile);

    if (pe && !ret_val)
    {
        memset(pe, 0, lpFileSize.LowPart);
        intFree(pe);
        pe = NULL;
    }

    return ret_val;
}

PSAVED_PE find_pe_by_name(
    IN LPSTR pe_name)
{
    PSAVED_PE saved_pe = NULL;

    saved_pe = BeaconGetValue(NC_SAVED_PE_KEY);
    while (saved_pe)
    {
        if (!_stricmp(saved_pe->pe_name, pe_name))
            break;

        saved_pe = saved_pe->next;
    }

    if (!saved_pe)
    {
        DPRINT("%s was not found", pe_name);
        return NULL;
    }

    return saved_pe;
}

VOID run_xor_on_pe(
    IN PSAVED_PE saved_pe)
{
    PBYTE xor_key = NULL;
    BYTE  tmp     = 0;

    xor_key = intAlloc(saved_pe->xor_length);
    if (!xor_key)
    {
        malloc_failed();
        return;
    }
    memcpy(xor_key, saved_pe->xor_key, saved_pe->xor_length);

    if (saved_pe->encrypted)
    {
        // decrypt
        for (int i = 0; i < saved_pe->pe_size; ++i)
        {
            tmp = saved_pe->pe_base[i];
            saved_pe->pe_base[i] ^= xor_key[i % saved_pe->xor_length];
            xor_key[i % saved_pe->xor_length] = tmp;
        }
    }
    else
    {
        // encrypt
        for (int i = 0; i < saved_pe->pe_size; ++i)
        {
            saved_pe->pe_base[i] ^= xor_key[i % saved_pe->xor_length];
            xor_key[i % saved_pe->xor_length] = saved_pe->pe_base[i];
        }
    }

    memset(xor_key, 0, saved_pe->xor_length);
    intFree(xor_key);
    saved_pe->encrypted = !saved_pe->encrypted;
}

BOOL save_pe_info(
    IN LPSTR pe_name,
    IN PBYTE pe_bytes,
    IN int   pe_length,
    IN LPSTR username,
    IN LPSTR loadtime)
{
    PSAVED_PE saved_pe = NULL;
    PSAVED_PE tmp      = NULL;
    time_t   t         = { 0 };

    if (!pe_name || !pe_bytes || !pe_length)
        return TRUE;

    // check the PE is not already saved
    if (find_pe_by_name(pe_name))
    {
        DPRINT("The PE %s is already saved", pe_name);
        return TRUE;
    }

    VOID (WINAPI *srand) (int) = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "srand", 0);
    int (WINAPI *rand) (void)  = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "rand", 0);
    time_t (WINAPI* time) (time_t*) = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "time", 0);

    if (!srand)
    {
        api_not_found("srand");
        return FALSE;
    }

    if (!rand)
    {
        api_not_found("rand");
        return FALSE;
    }

    if (!time)
    {
        api_not_found("time");
        return FALSE;
    }

    // allocate the SAVED_PE structure
    saved_pe = intAlloc(sizeof(SAVED_PE));

    // generate a random XOR key
    srand((unsigned) time(&t));

    saved_pe->xor_length = rand() & (256 - 1);

    if (saved_pe->xor_length < MIN_XOR_KEY_LENGTH)
        saved_pe->xor_length = MIN_XOR_KEY_LENGTH;

    saved_pe->xor_key = intAlloc(saved_pe->xor_length);

    for (int i = 0; i < saved_pe->xor_length; ++i)
    {
        saved_pe->xor_key[i] = rand() & (256 - 1);
    }

    // store the PE
    saved_pe->pe_size = pe_length;
    saved_pe->pe_base = intAlloc(saved_pe->pe_size);
    if (!saved_pe->pe_base)
    {
        function_failed("malloc");
        return FALSE;
    }

    memcpy(saved_pe->pe_base, pe_bytes, pe_length);

    // encrypt the PE
    run_xor_on_pe(saved_pe);
    StringCopyA(saved_pe->pe_name, pe_name);
    StringCopyA(saved_pe->username, username);
    StringCopyA(saved_pe->loadtime, loadtime);

    // add PE to linked list
    tmp = BeaconGetValue(NC_SAVED_PE_KEY);
    if (!tmp)
    {
        // save the PE linked list
        if (!BeaconAddValue(NC_SAVED_PE_KEY, saved_pe))
        {
            function_failed("BeaconAddValue");
            return FALSE;
        }
    }
    else
    {
        while (tmp)
        {
            if (!tmp->next)
            {
                tmp->next = saved_pe;
                break;
            }

            tmp = tmp->next;
        }
    }

    return TRUE;
}

BOOL get_saved_pe(
    IN  LPSTR  pe_name,
    OUT PVOID* data,
    OUT int*   pelen)
{
    PSAVED_PE saved_pe = NULL;

    saved_pe = find_pe_by_name(pe_name);
    if (!saved_pe)
        return FALSE;

    DPRINT("Found %s", saved_pe->pe_name);

    if (saved_pe->encrypted)
    {
        // decrypt the PE
        run_xor_on_pe(saved_pe);

        DPRINT("decrypted binary")
    }

    *data  = saved_pe->pe_base;
    *pelen = saved_pe->pe_size;

    return TRUE;
}

BOOL reencrypt_pe(
    IN LPSTR pe_name)
{
    PSAVED_PE saved_pe = NULL;

    saved_pe = find_pe_by_name(pe_name);
    if (!saved_pe)
        return FALSE;

    if (!saved_pe->encrypted)
    {
        // encrypt the PE
        run_xor_on_pe(saved_pe);

        DPRINT("reencrypted %s", saved_pe->pe_name);
    }

    return TRUE;
}

VOID list_saved_pes()
{
    PSAVED_PE saved_pe = NULL;

    saved_pe = BeaconGetValue(NC_SAVED_PE_KEY);
    if (!saved_pe)
    {
        PRINT("There are no saved PEs in memory");
    }
    else
    {
        PRINT("Saved PEs:");
        while (saved_pe)
        {
            PRINT("- name: %s, loaded by: %s, time: %s", saved_pe->pe_name, saved_pe->username, saved_pe->loadtime);
            saved_pe = saved_pe->next;
        }
    }
}

BOOL remove_saved_pe(
    IN  LPSTR  pe_name)
{
    PSAVED_PE saved_pe = NULL;
    PSAVED_PE tmp      = NULL;

    // look for the PE by name
    saved_pe = BeaconGetValue(NC_SAVED_PE_KEY);
    while (saved_pe)
    {
        if (!_stricmp(saved_pe->pe_name, pe_name))
        {
            // remove PE from linked list
            if (!tmp)
            {
                if (!BeaconRemoveValue(NC_SAVED_PE_KEY))
                {
                    function_failed("BeaconRemoveValue");
                    return FALSE;
                }

                if (saved_pe->next)
                {
                    if (!BeaconAddValue(NC_SAVED_PE_KEY, saved_pe->next))
                    {
                        function_failed("BeaconAddValue");
                        return FALSE;
                    }
                }
            }
            else
            {
                tmp->next = saved_pe->next;
            }

            break;
        }

        tmp = saved_pe;
        saved_pe = saved_pe->next;
    }

    if (!saved_pe)
    {
        DPRINT("%s was not found", pe_name);
        return FALSE;
    }

    memset(saved_pe->xor_key, 0, saved_pe->xor_length);
    intFree(saved_pe->xor_key);

    memset(saved_pe->pe_base, 0, saved_pe->pe_size);
    intFree(saved_pe->pe_base);

    memset(saved_pe, 0, sizeof(SAVED_PE));
    intFree(saved_pe);

    return TRUE;
}

#ifdef _WIN64

/*
 * The .mrdata section where the inverted function table
 * is stored is read-only by default, we need to set it to
 * read-write before we add a new entry and restore it
 * once we are done
 */
BOOL protect_inverted_function_table(
    IN BOOL protect)
{
    PVOID                  stBegin   = 0;
    SIZE_T                 len       = 0;
    PIMAGE_NT_HEADERS      nt        = NULL;
    PIMAGE_SECTION_HEADER  pSection  = NULL;
    DWORD                  newprot   = protect ? PAGE_READONLY : PAGE_READWRITE;
    DWORD                  oldprot   = 0;
    NTSTATUS               status    = STATUS_UNSUCCESSFUL;
    PIMAGE_DOS_HEADER      dos       = NULL;

    dos = xGetLibAddress("ntdll", TRUE, NULL);
    nt  = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);

    // find the .mrdata section
    pSection = IMAGE_FIRST_SECTION(nt);
    for (INT i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!strncmp(".mrdata", (LPCSTR)pSection->Name, 8))
        {
            stBegin = RVA2VA(PVOID, dos, pSection->VirtualAddress);
            len = pSection->Misc.VirtualSize;
            break;
        }

        ++pSection;
    }

    if (!stBegin || !len)
    {
        DPRINT("Failed to find section");
        return FALSE;
    }

    status = NtProtectVirtualMemory(NtCurrentProcess(), &stBegin, &len, newprot, &oldprot);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtProtectVirtualMemory", status);
        return FALSE;
    }

    return TRUE;
}

/*
 * The inverted function table is stored at .mrdata
 * and it holds one entry for each currently loaded DLL
 * that has an exception directory.
 * We can find it in memory by loking for NTDLL's entry
 * which is always first in the array.
 */
PVOID find_inverted_function_table()
{
    PVOID                         stEnd       = 0;
    PVOID                         stBegin     = 0;
    DWORD                         dwLen       = 0;
    DWORD                         rva         = 0;
    SIZE_T                        stRet       = 0;
    PIMAGE_NT_HEADERS             nt          = NULL;
    PIMAGE_SECTION_HEADER         pSection    = NULL;
    INVERTED_FUNCTION_TABLE_ENTRY ntdll_entry = { 0 };
    PIMAGE_DOS_HEADER             dos         = NULL;

    // reference: https://github.com/bats3c/DarkLoadLibrary/blob/6de15faa2cbc2b909500a67e854980deb0c0ba8c/DarkLoadLibrary/src/pebutils.c#L59

    dos = xGetLibAddress("ntdll", TRUE, NULL);
    nt  = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

    // create a copy of NTDLL's entry so we know what we are looking for
    ntdll_entry.FunctionTable = RVA2VA(PVOID, dos, rva);
    ntdll_entry.ImageBase     = dos;
    ntdll_entry.SizeOfImage   = nt->OptionalHeader.SizeOfImage;
    ntdll_entry.SizeOfTable   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    // find the .mrdata section on NTDLL
    pSection = IMAGE_FIRST_SECTION(nt);
    for (INT i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!strncmp(".mrdata", (LPCSTR)pSection->Name, 8))
        {
            stBegin = RVA2VA(PVOID, dos, pSection->VirtualAddress);
            dwLen = pSection->Misc.VirtualSize;
            break;
        }

        ++pSection;
    }

    if (!stBegin || !dwLen)
    {
        DPRINT("Failed to find section");
        return NULL;
    }

    // look for NTDLL's entry
    for (DWORD i = 0; i < dwLen - sizeof(INVERTED_FUNCTION_TABLE_ENTRY); ++i)
    {
        stRet = RtlCompareMemory(stBegin, &ntdll_entry, sizeof(INVERTED_FUNCTION_TABLE_ENTRY));

        if (stRet == sizeof(INVERTED_FUNCTION_TABLE_ENTRY))
        {
            stEnd = stBegin;
            break;
        }

        stBegin = RVA2VA(PVOID, stBegin, 1);
    }

    if (!stEnd)
    {
        DPRINT("Failed to find inverted function table");
        return NULL;
    }

    // get the base of the structure
    stEnd = CONTAINING_RECORD(stEnd, INVERTED_FUNCTION_TABLE_KERNEL_MODE, TableEntry);

    return stEnd;
}

/*
 * The code below is (mostly) equivalent to ntdll!RtlpInsertInvertedFunctionTableEntry,
 * but we do this by hand because that API is not exported by NTDLL.
 * Given that we are dealing with internal undocumented Windows structures,
 * there is no guarantee that this will work on older or newer versions.
 * This has been tested on Windows 10.0.19045, YMMV
 */
BOOL insert_inverted_function_table_entry(
    IN PVOID base_address,
    IN SIZE_T size_of_image,
    IN PRUNTIME_FUNCTION func_table,
    IN DWORD size_of_table)
{
    BOOL                                 Success   = FALSE;
    BOOL                                 is_unprot = FALSE;
    DWORD                                num_elems = 0;
    PINVERTED_FUNCTION_TABLE_KERNEL_MODE ift       = NULL;
    PINVERTED_FUNCTION_TABLE_ENTRY       fte       = NULL;

    ift = find_inverted_function_table();
    if (!ift)
        goto Cleanup;

    if (!protect_inverted_function_table(FALSE))
        goto Cleanup;

    is_unprot = TRUE;

    if (ift->CurrentSize == ift->MaximumSize)
    {
        ift->Overflow = 1;
        DPRINT("Too many entries in the inverted function table");
        goto Cleanup;
    }

    //ift->Epoch++;
    num_elems = 1;
    if (ift->CurrentSize != 1)
    {
        if (ift->CurrentSize > 1)
        {
            // ntdll is always at 0, so we start at 1
            fte = &ift->TableEntry[1];
            do
            {
                if (base_address < fte->FunctionTable)
                    break;

                num_elems++;
                fte++;
            } while(num_elems < ift->CurrentSize);
        }

        if (num_elems != ift->CurrentSize)
        {
            memcpy(
                &ift->TableEntry[num_elems + 1],
                &ift->TableEntry[num_elems],
                (ift->CurrentSize - num_elems) * sizeof(INVERTED_FUNCTION_TABLE_ENTRY));
        }
    }

    ift->TableEntry[num_elems].FunctionTable = func_table;
    ift->TableEntry[num_elems].ImageBase     = base_address;
    ift->TableEntry[num_elems].SizeOfImage   = size_of_image;
    ift->TableEntry[num_elems].SizeOfTable   = size_of_table;

    ift->CurrentSize++;
    //ift->Epoch++;

    Success = TRUE;

Cleanup:
    if (is_unprot)
        protect_inverted_function_table(TRUE);

    return Success;
}

/*
 * Once we are done, we remove our entry from the inverted function table
 */
BOOL remove_inverted_function_table_entry(
    IN PRUNTIME_FUNCTION func_table)
{
    BOOL                                 Success   = FALSE;
    BOOL                                 is_unprot = FALSE;
    PINVERTED_FUNCTION_TABLE_KERNEL_MODE ift       = NULL;
    PINVERTED_FUNCTION_TABLE_ENTRY       fte       = NULL;

    ift = find_inverted_function_table();
    if (!ift)
        goto Cleanup;

    for (DWORD i = 1; i < ift->CurrentSize; ++i)
    {
        fte = &ift->TableEntry[i];

        if (fte->FunctionTable == func_table)
        {
            if (!protect_inverted_function_table(FALSE))
                goto Cleanup;

            is_unprot = TRUE;

            if (ift->CurrentSize != i + 1)
            {
                memcpy(
                    &ift->TableEntry[i],
                    &ift->TableEntry[i + 1],
                    (ift->CurrentSize - i - 1) * sizeof(INVERTED_FUNCTION_TABLE_ENTRY));
            }

            ift->CurrentSize--;

            break;
        }
    }

    Success = TRUE;

Cleanup:
    if (is_unprot)
        protect_inverted_function_table(TRUE);

    return Success;
}

#endif // _WIN64
