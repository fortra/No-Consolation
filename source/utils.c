#include "utils.h"
#include <stddef.h>

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
    PLIB_LOADED lib_loaded = NULL;

    if (!peinfo)
        return;

    if (!peinfo->unload_libs)
        return;

    // first, check we didn't include this lib already
    lib_loaded = peinfo->libs_loaded;
    while (lib_loaded)
    {
        if (lib_loaded->address == dll)
            return;

        lib_loaded = lib_loaded->next;
    }

    // add this DLL to the linked list
    lib_loaded = intAlloc((sizeof(LIB_LOADED)));
    if (!lib_loaded)
        return;
    memcpy(lib_loaded->name, name, MAX_PATH);
    lib_loaded->address = dll;
    lib_loaded->next    = peinfo->libs_loaded;
    peinfo->libs_loaded = lib_loaded;
}

/*
 * Some PEs will search for APIs at runtime
 * we need to spoof these as well if we want to prevent
 * our process from exiting.
 * PsExec searches for mscoree!CorExitProcess and calls it if found.
 * This only happens if the CLR is loaded (i.e. PowerShell has been run)
 */
FARPROC my_get_proc_address(
    IN HMODULE hModule,
    IN LPSTR lpProcName)
{
    if (IsExitAPI(lpProcName))
    {
        DPRINT("Replacing %p!%s with ntdll!RtlExitUserThread", hModule, lpProcName);
        return xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlExitUserThread", 0);
    }

    FARPROC ( WINAPI *GetProcAddress ) ( HMODULE, LPSTR ) = xGetProcAddress(xGetLibAddress("kernel32", TRUE, NULL), "GetProcAddress", 0);
    if ( GetProcAddress )
    {
        return GetProcAddress(hModule, lpProcName);
    }
    else
    {
        api_not_found("GetProcAddress");
        return NULL;
    }
}

/*
 * If the PE calls GetModuleHandleW(NULL), we need to return
 * the base of our module, instead of the base of the host process
 */
HMODULE my_get_module_handle_w(
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

    memcpy(saved_pe->pe_name, pe_name, MAX_PATH);
    memcpy(saved_pe->username, username, MAX_PATH);
    memcpy(saved_pe->loadtime, loadtime, MAX_PATH);

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
        if (!strcmp(".mrdata", (LPCSTR)pSection->Name))
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
        if (!strcmp(".mrdata", (LPCSTR)pSection->Name))
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
    stEnd = RVA2VA(PVOID, stEnd, - offsetof(INVERTED_FUNCTION_TABLE_KERNEL_MODE, TableEntry));

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
            fte = &ift->TableEntry[0];
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

    for (DWORD i = 0; i < ift->CurrentSize; ++i)
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

#endif
