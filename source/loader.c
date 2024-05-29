
#include "loader.h"

BOOL load_pe(
    IN PVOID pedata,
    IN UINT32 pelen,
    OUT PLOADED_PE_INFO peinfo)
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
    BOOL                        loaded      = FALSE;

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
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &pe_base, 0, &pe_size, MEM_COMMIT, PAGE_READWRITE);
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

        // Update the actual address of the section
        sh[i].Misc.PhysicalAddress = (DWORD)*dest;

        DPRINT("Copied %s", sh[i].Name);
    }

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

            dll = xGetLibAddress(name, TRUE, &loaded);

            if (!dll)
            {
                DPRINT_ERR("Failed to load %s", name);
                goto Cleanup;
            }

            // remember we loaded this DLL
            store_loaded_dll(peinfo, dll, name);
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

                    // if this is an exit-related API, replace it with RtlExitUserThread
                    if (IsExitAPI(ibn->Name))
                    {
                        DPRINT("IAT hooking %s!%s with ntdll!RtlExitUserThread", name, ibn->Name);
                        ft->u1.Function = (ULONG_PTR)xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlExitUserThread", 0);
                    }
                    else if (!_stricmp(ibn->Name, "GetProcAddress"))
                    {
                        DPRINT("IAT hooking %s!%s with my_get_proc_address", name, ibn->Name);
                        ft->u1.Function = (ULONG_PTR)my_get_proc_address;
                    }
                    else if (!_stricmp(ibn->Name, "GetModuleHandleW"))
                    {
                        DPRINT("IAT hooking %s!%s with my_get_module_handle_w", name, ibn->Name);
                        ft->u1.Function = (ULONG_PTR)my_get_module_handle_w;
                    }
                    else
                    {
                        ft->u1.Function = (ULONG_PTR)xGetProcAddress(dll, ibn->Name, 0);
                    }

                    if (!ft->u1.Function)
                    {
                        DPRINT_ERR("Failed get address of %s!%s", name, ibn->Name);
                        goto Cleanup;
                    }
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

            dll = xGetLibAddress(name, TRUE, &loaded);

            if (dll == NULL) continue;

            // remember we loaded this DLL
            store_loaded_dll(peinfo, dll, name);

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
                    ft->u1.Function = (ULONG_PTR)xGetProcAddress(dll, ibn->Name, 0);
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

    if (!SetCommandLineW(peinfo->cmdwline))
    {
        goto Cleanup;
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

    peinfo->pe_base = pe_base;
    peinfo->pe_size = pe_size;

    return TRUE;

Cleanup:
    if (pe_base)
    {
#ifdef _WIN64
        if (peinfo->func_table)
        {
            remove_inverted_function_table_entry(peinfo->func_table);
            peinfo->func_table = NULL;
        }
#endif

        if (peinfo->linked)
        {
            unlink_module(peinfo->ldr_entry);
            peinfo->linked = FALSE;
        }

        peinfo->pe_base = pe_base;
        peinfo->pe_size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &peinfo->pe_base, &peinfo->pe_size, MEM_RELEASE);
        if (!NT_SUCCESS(status))
        {
            syscall_failed("NtFreeVirtualMemory", status);
            PRINT_ERR("Failed to cleanup PE from memory");
        }
    }

    peinfo->pe_base = NULL;

    return FALSE;
}

// check each exit-related api with name provided
BOOL IsExitAPI(
    IN PCHAR name)
{
    PCHAR str      = NULL;
    CHAR  api[128] = { 0 };
    INT   i        = 0;

    str = "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit;CorExitProcess\0";

    for (;;)
    {
        // store string until null byte or semi-colon encountered
        for (i = 0; str[i] != '\0' && str[i] != ';' && i < 128; i++) api[i] = str[i];
        // nothing stored? end
        if (i == 0) break;
        // skip name plus one for separator
        str += (i + 1);
        // store null terminator
        api[i] = '\0';
        // if equal, return TRUE
        if (!_stricmp(api, name)) return TRUE;
    }
    return FALSE;
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
