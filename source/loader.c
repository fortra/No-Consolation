
#include "loader.h"

VOID unload_dependency(
    IN PLOADED_PE_INFO peinfo)
{
    //DllMain_t DllMain = NULL;
    NTSTATUS  status  = STATUS_UNSUCCESSFUL;
    //FP        fp      = { 0 };

    if (!peinfo || !peinfo->pe_base)
        return;

    if (!peinfo->dont_unload && peinfo->custom_loaded)
    {
        if (peinfo->is_dll && peinfo->DllMain)
        {
            /*
             * Calling DllMain with DLL_PROCESS_DETACH seems to break future
             * loads of mscoree.dll, so we avoid it
             */

            //DPRINT("Executing DllMain(hinstDLL, DLL_PROCESS_DETACH, NULL) for %s", peinfo->pe_name);
            //DllMain = peinfo->DllMain;
            //DllMain(peinfo->pe_base, DLL_PROCESS_DETACH, NULL);
        }

        /*
        if (!peinfo->is_dependency && peinfo->handled_tls)
        {
            fp.ptr = find_ldrp_release_tls_entry();;
            if (fp.ptr)
                fp.thiscall(peinfo->ldr_entry);
        }
        /*/

#ifdef _WIN64
        if (peinfo->func_table)
            remove_inverted_function_table_entry(peinfo->func_table);
#endif

        if (peinfo->linked)
            unlink_module(peinfo->ldr_entry);

        if (peinfo->ldr_entry)
        {
            memset(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->BaseDllName.Buffer, 0, sizeof(WCHAR) * MAX_PATH);
            intFree(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->BaseDllName.Buffer);
            memset(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->FullDllName.Buffer, 0, sizeof(WCHAR) * MAX_PATH);
            intFree(((PLDR_DATA_TABLE_ENTRY2)peinfo->ldr_entry)->FullDllName.Buffer);
            memset(peinfo->ldr_entry, 0, sizeof(PLDR_DATA_TABLE_ENTRY2));
            intFree(peinfo->ldr_entry);
        }

        if (peinfo->pe_base)
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
}

BOOL find_dll(
    IN PLOADED_PE_INFO dep,
    IN LPSTR dll_name,
    OUT PVOID* pe_bytes,
    OUT int* pe_length)
{
    LPSTR search_paths      = dep->search_paths ? dep->search_paths : "C:\\Windows\\System32\\\0";
    CHAR  pe_path[MAX_PATH] = { 0 };
    DWORD i                 = 0;

    for (;;)
    {
        // store string until null byte, semi-colon or comma encountered
        for (i = 0; search_paths[i] != '\0' &&
                    search_paths[i] != ';' &&
                    search_paths[i] != ','; i++) pe_path[i] = search_paths[i];
        // nothing stored? end
        if (i == 0) break;
        // skip name plus one for separator
        search_paths += (i + 1);
        // ensure the path ends with a backslash
        if (pe_path[i-1] != '\\')
        {
            pe_path[i] = '\\';
            i++;
        }
        // store null terminator
        pe_path[i] = '\0';
        // add the name of the DLL
        StringConcatA(pe_path, dll_name);
        // try to read the PE
        if (read_local_pe(pe_path, pe_bytes, pe_length))
        {
            // set the PE path
            CharStringToWCharString(dep->pe_wpath, pe_path, MAX_PATH);
            return TRUE;
        }
    }

    DPRINT_ERR("Failed to find %s", dll_name);

    return FALSE;
}

BOOL load_dependency(
    IN PLOADED_PE_INFO dep,
    IN LPSTR dll_name)
{
    PVOID pe_bytes  = NULL;
    int   pe_length = 0;

    if (!find_dll(dep, dll_name, &pe_bytes, &pe_length))
        return FALSE;

    return load_pe(pe_bytes, pe_length, dep);
}

PVOID handle_dependency(
    IN PLOADED_PE_INFO peinfo,
    IN LPSTR dll_name)
{
    LPSTR           name        = NULL;
    BOOL            api_set_ok  = FALSE;
    PVOID           dll         = NULL;
    PLOADED_PE_INFO dep         = NULL;
    PLIB_LOADED     lib_loaded  = NULL;
    PLIBS_LOADED    libs_loaded = NULL;

    // resolve the API Set
    name = api_set_resolve(dll_name);
    api_set_ok = name != NULL;
    if (!api_set_ok)
        name = dll_name;

    // if the name is empty, just return (this happens with ext-ms-win32-subsystem-query-l1-1-0.dll)
    if (name[0] == '\0') return NULL;

    // check if the DLL is already loaded
    dll = xGetLibAddress(name, FALSE, NULL);

    if (!dll)
    {
        /*
         * Here we handle a peculiar edge case:
         * 1) we are loading mprext.dll and realize it requires MPR.dll
         * 2) we start loading MPR.dll and realize it requires mprext.dll
         * 3) we then find the incomplete load of mprext.dll in memory and parse it
         *    in order to find the addresses of its exported functions
         * 4) we finish loading MPR.dll
         * 5) we finish loading mprext.dll
         */

        libs_loaded = BeaconGetValue(NC_LOADED_DLL_KEY);

        lib_loaded = (PLIB_LOADED)libs_loaded->list.Flink;
        while (&lib_loaded->list != &libs_loaded->list)
        {
            if (!_stricmp(lib_loaded->peinfo->pe_name, name))
            {
                // found it
                if (!lib_loaded->peinfo->pe_base && !lib_loaded->peinfo->custom_loaded)
                {
                    /*
                     * We loaded this DLL via LoadLibrary before and it returned 0x0.
                     * Simply return 0x0 as this DLL does not seem to exist
                     */

                    return NULL;
                }

                // return its base
                dll = lib_loaded->peinfo->pe_base;
                break;
            }

            lib_loaded = (PLIB_LOADED)lib_loaded->list.Flink;
        }
    }

    if (!dll && peinfo)
    {
        dep = intAlloc(sizeof(LOADED_PE_INFO));
        StringCopyA(dep->pe_name, name);
        CharStringToWCharString(dep->pe_wname, name, MAX_PATH);
        dep->link_to_peb   = peinfo->link_to_peb;
        dep->dont_unload   = peinfo->dont_unload;
        dep->is_dependency = TRUE;
        dep->load_all_deps = peinfo->load_all_deps;
        dep->load_all_deps_but = peinfo->load_all_deps_but;
        dep->load_deps     = peinfo->load_deps;
        dep->search_paths  = peinfo->search_paths;

        store_loaded_dll(dep, dll, name);
    }

    // if not already loaded, custom load it if the operator so chooses
    if (!dll && peinfo &&
        (peinfo->load_all_deps ||
        (peinfo->load_all_deps_but && !string_is_included(peinfo->load_all_deps_but, name)) ||
        (peinfo->load_deps && string_is_included(peinfo->load_deps, name))))
    {

        DPRINT("%s depends on %s, custom loading...", peinfo->pe_name, name);
        if (load_dependency(dep, name))
        {
            DPRINT("Finished loading %s, continuing with %s", name, peinfo->pe_name);
            dep->custom_loaded = TRUE;
            dll = dep->pe_base;
        }
        else
        {
            PRINT_ERR("Failed to custom load %s", name);
        }
    }

    // fallback to LoadLibrary
    if (!dll)
    {
        dll = LoadLibraryA(name);
        if (peinfo)
        {
            DPRINT("Loaded %s via LoadLibrary at 0x%p, continuing with %s", name, dll, peinfo->pe_name);
        }
        else
        {
            DPRINT("Loaded %s via LoadLibrary at 0x%p", name, dll);
        }
        if (dep)
        {
            dep->custom_loaded = FALSE;
            dep->pe_base       = dll;
        }
    }

    if (api_set_ok)
    {
        memset(name, 0, MAX_PATH);
        intFree(name);
    }

    return dll;
}

PVOID handle_import(
    IN PLOADED_PE_INFO peinfo,
    IN PVOID dll_base,
    IN LPSTR dll_name,
    IN LPSTR api_name)
{
    PVOID address = NULL;

    /*
     * Here we implement our IAT hooking.
     * If the PE was run with --dont-unload, we don't redirect imports
     * to this BOF, as this will be offloaded soon.
     */

    // if this is an exit-related API, replace it with RtlExitUserThread
    if (IsExitAPI(api_name))
    {
        DPRINT("IAT hooking %s!%s with rtl_exit_user_thread", dll_name ? dll_name : "?", api_name);
        address = rtl_exit_user_thread;
    }
    // some PEs search for exit-related APIs using GetProcAddress
    else if (peinfo && !peinfo->dont_unload && !peinfo->is_dependency && !_stricmp(api_name, "GetProcAddress"))
    {
        DPRINT("IAT hooking %s!%s with my_get_proc_address", dll_name ? dll_name : "?", api_name);
        address = my_get_proc_address;
    }
    // PEs call GetModuleHandleW(NULL), we ensure this returns their base address
    else if (peinfo && !peinfo->dont_unload && !peinfo->is_dependency && !_stricmp(api_name, "GetModuleHandleW"))
    {
        DPRINT("IAT hooking %s!%s with my_get_module_handle_w", dll_name ? dll_name : "?", api_name);
        address = my_get_module_handle_w;
    }
    // resolve the API without IAT hook
    else
    {
        address = xGetProcAddress(dll_base, api_name, 0);
    }

    if (!address)
    {
        DPRINT_ERR("Failed get address of %s!%s", dll_name ? dll_name : "?", api_name);
    }

    return address;
}

BOOL load_pe(
    IN PVOID pedata,
    IN UINT32 pelen,
    IN OUT PLOADED_PE_INFO peinfo)
{
    PIMAGE_DOS_HEADER           dos         = NULL;
    PIMAGE_NT_HEADERS           nt          = NULL;
    PIMAGE_NT_HEADERS           ntnew       = NULL;
    PIMAGE_SECTION_HEADER       sh          = NULL;
    PIMAGE_THUNK_DATA           oft         = NULL;
    PIMAGE_THUNK_DATA           ft          = NULL;
    PIMAGE_IMPORT_BY_NAME       ibn         = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    imp         = NULL;
    PIMAGE_DELAYLOAD_DESCRIPTOR del         = NULL;
    PIMAGE_EXPORT_DIRECTORY     exp         = NULL;
    PIMAGE_TLS_DIRECTORY        tls         = NULL;
    PIMAGE_TLS_CALLBACK         *callbacks  = NULL;
    PIMAGE_RELOC                list        = NULL;
    PIMAGE_BASE_RELOCATION      ibr         = NULL;
#ifdef _WIN64
    PRUNTIME_FUNCTION           func_table  = NULL;
#endif
    DWORD                       rva         = 0;
    DWORD                       size        = 0;
    PDWORD                      adr         = NULL;
    PDWORD                      sym         = NULL;
    PWORD                       ord         = NULL;
    PBYTE                       ofs         = NULL;
    PCHAR                       str         = NULL;
    PCHAR                       name        = NULL;
    HMODULE                     dll         = NULL;
    LPVOID                      base        = NULL;
    DWORD                       i           = 0;
    DWORD                       cnt         = 0;
    PVOID                       baseAddress = NULL;
    SIZE_T                      numBytes    = 0;
    DWORD                       newprot     = 0;
    DWORD                       oldprot     = 0;
    NTSTATUS                    status      = STATUS_UNSUCCESSFUL;
    PVOID                       pe_base     = NULL;
    SIZE_T                      pe_size     = 0;
    BOOL                        has_reloc   = FALSE;
    DllMain_t                   DllMain     = NULL;
    FP                          fp          = { 0 };

    if (!is_pe(pedata))
    {
        DPRINT_ERR("The data is not a PE");
        goto Cleanup;
    }

    peinfo->is_dll = is_dll(pedata);

    base = pedata;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);

    if (nt->FileHeader.Machine != MACHINE)
    {
        PRINT_ERR("Host process and PE are not compatible");
        goto Cleanup;
    }

    // check if the binary has relocation information
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    has_reloc = size == 0 ? FALSE : TRUE;
    if (!has_reloc)
    {
        pe_base = (PVOID)nt->OptionalHeader.ImageBase;
        DPRINT("No relocation information present, setting the base to: 0x%p", pe_base);
    }

    pe_size = nt->OptionalHeader.SizeOfImage;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &pe_base, 0, &pe_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        pe_base = NULL;
        syscall_failed("NtAllocateVirtualMemory", status);
        PRINT_ERR("Failed to allocate PE, address 0x%p seems to be in use", pe_base);
        goto Cleanup;
    }

    DPRINT("Mapped at 0x%p - 0x%p", pe_base, RVA2VA(PVOID, pe_base, pe_size));

    DPRINT("Copying Headers");
    memcpy(pe_base, base, nt->OptionalHeader.SizeOfHeaders);

    ntnew = RVA2VA(PIMAGE_NT_HEADERS, pe_base, dos->e_lfanew);
    ntnew->OptionalHeader.ImageBase = (ULONG_PTR)pe_base;

    DPRINT("Copying each section to memory");
    sh = IMAGE_FIRST_SECTION(ntnew);

    for (i = 0; i < ntnew->FileHeader.NumberOfSections; i++)
    {
        PBYTE dest = (PBYTE)pe_base + sh[i].VirtualAddress;
        PBYTE source = (PBYTE)base + sh[i].PointerToRawData;

        // Copy the section data
        memcpy(dest,
            source,
            sh[i].SizeOfRawData);

        DPRINT("Copied %s at 0x%p", sh[i].Name, dest);
    }

    peinfo->pe_base = pe_base;
    peinfo->pe_size = pe_size;

    ofs  = (PBYTE)pe_base - nt->OptionalHeader.ImageBase;

    if (has_reloc && ofs != 0)
    {
        DPRINT("Applying Relocations");

        rva  = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        ibr = RVA2VA(PIMAGE_BASE_RELOCATION, pe_base, rva);

        while ((PBYTE)ibr < ((PBYTE)pe_base + rva + size) && ibr->SizeOfBlock != 0)
        {
            list = (PIMAGE_RELOC)(ibr + 1);

            while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock)
            {
                // check that the RVA is within the boundaries of the PE
                if (ibr->VirtualAddress + list->offset < ntnew->OptionalHeader.SizeOfImage)
                {
                    PULONG_PTR address = (PULONG_PTR)((PBYTE)pe_base + ibr->VirtualAddress + list->offset);
                    if (list->type == IMAGE_REL_BASED_DIR64) {
                        *address += (ULONG_PTR)ofs;
                    } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
                        *address += (DWORD)(ULONG_PTR)ofs;
                    } else if (list->type == IMAGE_REL_BASED_HIGH) {
                        *address += HIWORD(ofs);
                    } else if (list->type == IMAGE_REL_BASED_LOW) {
                        *address += LOWORD(ofs);
                    } else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
                        DPRINT_ERR("ERROR: Unrecognized Relocation type %08lx.", list->type);
                        goto Cleanup;
                    }
                }
                list++;
            }
            ibr = (PIMAGE_BASE_RELOCATION)list;
        }
    }

#ifdef _WIN64
    rva  = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

    if (rva != 0)
    {
        /*
         * In this section, we try to add support for C++ Exceptions.
         * To achieve this, we update the inverted function table
         * given that this memory structure is (for some reason) important
         * while dealing with exceptions.
         */

        func_table = RVA2VA(PRUNTIME_FUNCTION, pe_base, rva);
        size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

        // most PE loaders do this but I haven't found it useful
        //RtlAddFunctionTable(func_table, size / sizeof(RUNTIME_FUNCTION), pe_base);

        if (!insert_inverted_function_table_entry(pe_base, pe_size, func_table, size))
        {
            DPRINT("Failed to insert new entry in the inverted function table");
            goto Cleanup;
        }

        // remember the function table so we can cleanup later
        peinfo->func_table = func_table;
    }
#endif

    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (rva != 0)
    {
        DPRINT("Processing the Import Table");

        imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, pe_base, rva);

        // For each DLL
        for (; imp->Name != 0; imp++)
        {
            name = RVA2VA(PCHAR, pe_base, imp->Name);

            dll = handle_dependency(peinfo, name);
            if (!dll)
            {
                DPRINT_ERR("Failed to load %s", name);
                goto Cleanup;
            }

            // remember if msvcrt gets loaded
            if (!_stricmp(name, "msvcrt.dll"))
                peinfo->loaded_msvcrt   = TRUE;
            // remember if mscoree gets loaded
            if (!_stricmp(name, "mscoree.dll"))
                peinfo->loaded_mscoree  = TRUE;
            // remember if ucrtbase gets loaded
            if (!_stricmp(name, "ucrtbase.dll") || !strncmp(name, "api-ms-win-crt", 14))
                peinfo->loaded_ucrtbase = TRUE;

            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, pe_base, imp->OriginalFirstThunk);
            ft  = RVA2VA(PIMAGE_THUNK_DATA, pe_base, imp->FirstThunk);

            // For each API
            for (;; oft++, ft++)
            {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;

                // Resolve by ordinal?
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal))
                {
                    ft->u1.Function = (ULONG_PTR)xGetProcAddress(dll, NULL, oft->u1.Ordinal);
                    if (!ft->u1.Function)
                    {
                        DPRINT_ERR("Failed get address of ordinal %d from %s", oft->u1.Ordinal, name);
                        goto Cleanup;
                    }
                }
                else
                {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, pe_base, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)handle_import(peinfo, dll, name, ibn->Name);

                    if (!ft->u1.Function)
                        goto Cleanup;
                }
            }
        }
    }

    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;

    if (rva != 0)
    {
        DPRINT("Processing Delayed Import Table");

        del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, pe_base, rva);

        // For each DLL
        for (; del->DllNameRVA != 0; del++)
        {
            name = RVA2VA(PCHAR, pe_base, del->DllNameRVA);

            dll = handle_dependency(peinfo, name);
            if (dll == NULL) continue;

            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, pe_base, del->ImportNameTableRVA);
            ft  = RVA2VA(PIMAGE_THUNK_DATA, pe_base, del->ImportAddressTableRVA);

            // For each API
            for (;; oft++, ft++)
            {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;

                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal))
                {
                    // Resolve by ordinal
                    ft->u1.Function = (ULONG_PTR)xGetProcAddress(dll, NULL, oft->u1.Ordinal);
                }
                else
                {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, pe_base, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)handle_import(peinfo, dll, name, ibn->Name);
                }
            }
        }
    }

    DPRINT("Setting permissions for each PE section");
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            newprot = PAGE_WRITECOPY;

        if (sh[i].Characteristics & IMAGE_SCN_MEM_READ)
            newprot = PAGE_READONLY;

        if ((sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (sh[i].Characteristics & IMAGE_SCN_MEM_READ))
            newprot = PAGE_READWRITE;

        if (sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            newprot = PAGE_EXECUTE;

        if ((sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            newprot = PAGE_EXECUTE_WRITECOPY;

        if ((sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sh[i].Characteristics & IMAGE_SCN_MEM_READ))
            newprot = PAGE_EXECUTE_READ;

        if ((sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( sh[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( sh[i].Characteristics & IMAGE_SCN_MEM_READ ) )
            newprot = PAGE_EXECUTE_READWRITE;

        baseAddress = RVA2VA(PVOID, pe_base, sh[i].VirtualAddress);
        numBytes    = sh[i].SizeOfRawData;

        DPRINT("Section name: %s, size, 0x%llX, protections: 0x%X", sh[i].Name, numBytes, newprot);

        if (!numBytes)
            continue;

        status = NtProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &numBytes, newprot, &oldprot);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtProtectVirtualMemory", status);
            goto Cleanup;
        }
    }

    if (peinfo->headers)
    {
        DPRINT("Wiping Headers from memory");
        memset(pe_base, 0, nt->OptionalHeader.SizeOfHeaders);
    }

    // declare variables and set permissions of module header
    DPRINT("Setting permissions of module headers to READONLY (%d bytes)", nt->OptionalHeader.BaseOfCode);
    oldprot = 0;

    baseAddress = pe_base;
    numBytes    = nt->OptionalHeader.BaseOfCode;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &numBytes, PAGE_READONLY, &oldprot);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtProtectVirtualMemory", status);
        goto Cleanup;
    }

    DPRINT("Flushing instructionCache");
    status = NtFlushInstructionCache(NtCurrentProcess(), NULL, 0);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtFlushInstructionCache", status);
        goto Cleanup;
    }

    // find the entry point of the PE
    if (peinfo->is_dll)
    {
        // some DLLs don't have an entry point
        if (nt->OptionalHeader.AddressOfEntryPoint)
            peinfo->DllMain = RVA2VA(PVOID, pe_base, nt->OptionalHeader.AddressOfEntryPoint);
        else
            peinfo->DllMain = NULL;

        if (peinfo->method)
        {
            DPRINT("Resolving address of %s", peinfo->method);

            rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, pe_base, rva);

            if (rva != 0)
            {
                cnt = exp->NumberOfNames;

                if (cnt != 0)
                {
                    adr = RVA2VA(PDWORD,pe_base, exp->AddressOfFunctions);
                    sym = RVA2VA(PDWORD,pe_base, exp->AddressOfNames);
                    ord = RVA2VA(PWORD, pe_base, exp->AddressOfNameOrdinals);

                    do {
                        str = RVA2VA(PCHAR, pe_base, sym[cnt-1]);
                        if (!_stricmp(str, peinfo->method))
                        {
                            peinfo->DllParam = RVA2VA(PVOID, pe_base, adr[ord[cnt-1]]);
                            break;
                        }
                    } while (--cnt);

                    if (!peinfo->DllParam)
                    {
                        DPRINT_ERR("Unable to resolve %s", peinfo->method);
                        goto Cleanup;
                    }
                }
            }
        }
    }
    else
    {
        peinfo->EntryPoint = RVA2VA(PVOID, pe_base, nt->OptionalHeader.AddressOfEntryPoint);
    }

    if (peinfo->link_to_peb)
    {
        DPRINT("Linking module to the PEB");

        if (!link_module(peinfo, pe_base))
        {
            DPRINT("Failed to link module to the PEB");
            goto Cleanup;
        }
        peinfo->linked = TRUE;
    }

    if (peinfo->ldr_entry)
    {
        DPRINT("Processing Thread Local Storage");

        fp.ptr = find_ldrp_handle_tls_data();;
        if (fp.ptr)
        {
            status = fp.thiscall(peinfo->ldr_entry);
            if (!NT_SUCCESS(status))
            {
                syscall_failed("LdrpHandleTlsData", status);
                goto Cleanup;
            }

            peinfo->handled_tls = TRUE;
        }
    }

    // Execute TLS callbacks
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (rva != 0)
    {
        DPRINT("Processing TLS directory");

        tls = RVA2VA(PIMAGE_TLS_DIRECTORY, pe_base, rva);

        // address of callbacks is absolute. requires relocation information
        callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        DPRINT("AddressOfCallBacks : %p", callbacks);

        if (callbacks)
        {
            while (*callbacks != NULL)
            {
                /*
                 * while TLS callbacks are called by this thread (meaning, no hwbp)
                 * this in unlikely to be an issue given that they are
                 * usually created by the compiler and should be harmless
                 */
                DPRINT("Calling %p", *callbacks);
                (*callbacks)((LPVOID)pe_base, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    // call DllMain if apropiate
    if (peinfo->is_dll && (peinfo->is_dependency || peinfo->method) && peinfo->DllMain)
    {
        DPRINT("Executing DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)");

        DllMain = peinfo->DllMain;
        DllMain(peinfo->pe_base, DLL_PROCESS_ATTACH, NULL);
    }

    if (!peinfo->is_dependency && !SetCommandLineW(peinfo->cmdwline))
    {
        goto Cleanup;
    }

    if (peinfo->dont_unload)
    {
        store_loaded_dll(peinfo, peinfo->pe_base, peinfo->pe_name);
    }

    peinfo->loaded = TRUE;

    return TRUE;

Cleanup:

    // TODO: cleanup?
    return FALSE;
}

// check each exit-related api with name provided
BOOL IsExitAPI(
    IN PCHAR name)
{
    PCHAR str = "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit;CorExitProcess\0";
    return string_is_included(str, name);
}

// returns TRUE if ptr is heap memory
BOOL IsHeapPtr(
    IN LPVOID ptr)
{
    NTSTATUS                 status = STATUS_UNSUCCESSFUL;
    MEMORY_BASIC_INFORMATION mbi    = { 0 };
    MEMORY_INFORMATION_CLASS mic    = 0;

    if (ptr == NULL) return FALSE;

    // query the pointer
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, mic, &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryVirtualMemory", status);
        return FALSE;
    }

    return (mbi.State   == MEM_COMMIT  &&
            mbi.Type    == MEM_PRIVATE &&
            mbi.Protect == PAGE_READWRITE);
}


// check if memory address can be read
BOOL IsReadable(
    IN LPVOID ptr)
{
    NTSTATUS                 status = STATUS_UNSUCCESSFUL;
    MEMORY_BASIC_INFORMATION mbi    = { 0 };
    MEMORY_INFORMATION_CLASS mic    = 0;

    if (ptr == NULL) return FALSE;

    // query the pointer
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, mic, &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtQueryVirtualMemory", status);
        return FALSE;
    }

    return (mbi.Protect == PAGE_READWRITE    ||
            mbi.Protect == PAGE_READONLY     ||
            mbi.Protect == PAGE_EXECUTE_READ ||
            mbi.Protect == PAGE_EXECUTE_READWRITE);
}

/*
 * Set the command line for host process.
 * This replaces kernelbase!BaseUnicodeCommandLine and kernelbase!BaseAnsiCommandLine
 * that kernelbase!KernelBaseDllInitialize reads from NtCurrentPeb()->ProcessParameters->CommandLine
 */
BOOL SetCommandLineW(
    IN PCWSTR CommandLine)
{
    PIMAGE_DOS_HEADER      dos      = NULL;
    PIMAGE_NT_HEADERS      nt       = NULL;
    PIMAGE_SECTION_HEADER  sh       = NULL;
    DWORD                  i        = 0;
    DWORD                  cnt      = 0;
    PULONG_PTR             ds       = NULL;
    HMODULE                m        = NULL;
    ANSI_STRING            ansi     = { 0 };
    PANSI_STRING           mbs      = NULL;
    PUNICODE_STRING        wcs      = NULL;
    PPEB2                  peb      = NULL;
    PPEB_LDR_DATA2         ldr      = NULL;
    PLDR_DATA_TABLE_ENTRY2 dte      = NULL;
    CHAR                   **argv   = NULL;
    WCHAR                  **wargv  = NULL;
    p_acmdln_t             p_acmdln = NULL;
    p_wcmdln_t             p_wcmdln = NULL;
    CHAR                   sym[128] = { 0 };
    PCHAR                  str      = NULL;
    INT                    fptr     = 0;
    INT                    atype    = 0;
    PVOID                  addr     = NULL;
    PVOID                  wcmd     = NULL;
    PVOID                  acmd     = NULL;

    if (!CommandLine)
        return TRUE;

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ldr = (PPEB_LDR_DATA2)peb->Ldr;

    m   = xGetLibAddress("KernelBase", TRUE, NULL);
    dos = (PIMAGE_DOS_HEADER)m;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader +
          nt->FileHeader.SizeOfOptionalHeader);

    // locate the .data segment, save VA and number of pointers
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (*(PDWORD)sh[i].Name == *(PDWORD)".data")
        {
            ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
            cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
            break;
        }
    }

    DPRINT("Searching %i pointers", cnt);

    wcmd = GetCommandLineW();

    for (i = 0; i < cnt; i++)
    {
        wcs = (PUNICODE_STRING)&ds[i];
        // skip if not equal
        if (wcs->Buffer != wcmd) continue;
        DPRINT("BaseUnicodeCommandLine found at %p:%p : %ls", &ds[i], wcs->Buffer, wcs->Buffer);
        // overwrite buffer for GetCommandLineW
        RtlCreateUnicodeString(wcs, CommandLine);
        DPRINT("GetCommandLineW() : %ls", GetCommandLineW());
        break;
    }

    acmd = GetCommandLineA();

    for (i = 0; i < cnt; i++)
    {
        mbs = (PANSI_STRING)&ds[i];
        // skip if not equal
        if (mbs->Buffer != acmd) continue;
        DPRINT("BaseAnsiCommandLine found at %p:%p : %s", &ds[i], mbs->Buffer, mbs->Buffer);
        RtlUnicodeStringToAnsiString(&ansi, wcs, TRUE);
        memcpy(&ds[i], &ansi, sizeof(ANSI_STRING));
        DPRINT("GetCommandLineA() : %s", GetCommandLineA());
        break;
    }

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY2)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL;
         dte=(PLDR_DATA_TABLE_ENTRY2)dte->InLoadOrderLinks.Flink)
    {
        // check for exported symbols and patch according to string type
        str = (PCHAR)"_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv\0";

        for (;;)
        {
            // reset flags
            atype = 1; fptr = 0;
            // store string until null byte or semi-colon encountered
            for (i = 0; str[i] != '\0' && str[i] != ';' && i < 128; i++)
            {
                // w indicates unicode type
                if (str[i] == 'w') atype = 0;
                // p indicates function pointer
                if (str[i] == 'p') fptr  = 1;
                // store byte
                sym[i] = str[i];
            }
            // nothing stored? end loop for this DLL
            if (i == 0) break;
            // skip name plus one for separator
            str += (i + 1);
            // store null terminator
            sym[i] = '\0';
            // see if it can be resolved for current module
            addr = xGetProcAddress(dte->DllBase, sym, 0);
            // nothing resolve? get the next symbol from list
            if (addr == NULL) continue;
            // is this ansi?
            if (atype)
            {
                argv = (PCHAR*)addr;
                // pointer?
                if (fptr != 0)
                {
                    p_acmdln = (p_acmdln_t)addr;
                    argv = p_acmdln();
                }
                // anything to patch?
                DPRINT("Checking %s", sym);
                if (IsReadable(argv) && IsHeapPtr(*argv))
                {
                    DPRINT("Setting %ls!%s \"%s\" to \"%s\"", dte->BaseDllName.Buffer, sym, *argv, ansi.Buffer);
                    *argv = ansi.Buffer;
                }
            }
            else
            {
                wargv = (PWCHAR*)addr;
                // pointer?
                if (fptr != 0)
                {
                    p_wcmdln = (p_wcmdln_t)addr;
                    wargv = p_wcmdln();
                }
                // anything to patch?
                DPRINT("Checking %s", sym);
                if (IsReadable(wargv) && IsHeapPtr(*wargv))
                {
                    DPRINT("Setting %ls!%s \"%ls\" to \"%ls\"", dte->BaseDllName.Buffer, sym, *wargv, wcs->Buffer);
                    *wargv = wcs->Buffer;
                }
            }
        }
    }

    return TRUE;
}
