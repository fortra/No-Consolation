#include "utils.h"

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
    memcpy(lib_loaded->name, name, MAX_PATH);
    lib_loaded->address = dll;
    lib_loaded->next    = peinfo->libs_loaded;
    peinfo->libs_loaded = lib_loaded;
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
