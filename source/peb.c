
#include "peb.h"
#include "loader.h"

// find a DLL with a certain export, used by xGetProcAddress and FindExport
LPVOID find_reference(
    IN LPVOID original_dll,
    IN PCHAR dll_name,
    IN PCHAR api_name)
{
    PPEB                  peb  = NULL;
    PPEB_LDR_DATA         ldr  = NULL;
    PLDR_DATA_TABLE_ENTRY dte  = NULL;
    LPVOID                addr = NULL;
    LPVOID                base = NULL;

    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    ldr = (PPEB_LDR_DATA)peb->Ldr;

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->Reserved2[1];
       dte->DllBase != NULL && addr == NULL;
       dte=(PLDR_DATA_TABLE_ENTRY)dte->Reserved1[0])
    {
        base = dte->DllBase;
        // if this is the dll with the reference, continue
        if (base == original_dll) continue;

        addr = xGetProcAddress(base, api_name, 0);
    }
    if (addr == NULL)
    {
        // we did not find the reference, use GetProcAddress
        HMODULE hModule = xGetLibAddress(dll_name, TRUE, NULL);

        if (hModule != NULL)
        {
            DPRINT("Calling GetProcAddress(%s)", api_name);
            addr = GetProcAddress(hModule, api_name);
        }
        else
            addr = NULL;
    }

    return addr;
}

// search for an export in a DLL
LPVOID xGetProcAddress(
    IN LPVOID base,
    IN PCHAR api_name,
    IN DWORD ordinal)
{
    PIMAGE_DOS_HEADER       dos          = NULL;
    PIMAGE_NT_HEADERS       nt           = NULL;
    PIMAGE_DATA_DIRECTORY   dir          = NULL;
    PIMAGE_EXPORT_DIRECTORY exp          = NULL;
    LPVOID                  addr         = NULL;
    DWORD                   rva          = 0;
    DWORD                   cnt          = 0;
    PDWORD                  adr          = NULL;
    PDWORD                  sym          = NULL;
    PWORD                   ord          = NULL;
    PCHAR                   api          = NULL;
    CHAR                    dll_name[64] = { 0 };
    CHAR                    new_api[64]  = { 0 };
    DWORD                   i            = 0;
    PCHAR                   p            = NULL;

    if (base == NULL) return NULL;

    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // if no export table, return NULL
    if (rva == 0) return NULL;

    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

    if (api_name != NULL)
    {
        // exported by name
        cnt = exp->NumberOfNames;
        // if no api names, return NULL
        if (cnt == 0) return NULL;

        do {
            api = RVA2VA(PCHAR, base, sym[cnt-1]);
            // check if the export name matches the API we are looking for
            if (!_stricmp(api, api_name))
            {
                // get the address of the API
                addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
            }
        } while (--cnt && addr == NULL);
    }
    else
    {
        // exported by ordinal
        addr = RVA2VA(PVOID, base, adr[ordinal - exp->Base]);
    }

      // is this a forward reference?
    if ((PBYTE)addr >= (PBYTE)exp &&
      (PBYTE)addr <  (PBYTE)exp +
      dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
    {
        //DPRINT("%s is forwarded to %s", api_name, (char*)addr);

        // copy DLL name to buffer
        p=(char*)addr;

        for (i=0; p[i] != 0 && i < sizeof(dll_name) - 4; i++)
        {
            dll_name[i] = p[i];
            if(p[i] == '.') break;
        }

        dll_name[i+1] = 'd';
        dll_name[i+2] = 'l';
        dll_name[i+3] = 'l';
        dll_name[i+4] = 0;

        p += i + 1;

        // copy API name to buffer
        for(i = 0; p[i] != 0 && i < sizeof(new_api) - 1; i++)
        {
            new_api[i] = p[i];
        }
        new_api[i] = 0;

        addr = find_reference(base, dll_name, new_api);
    }
    return addr;
}

// find a DLL by name, load it if not found
LPVOID xGetLibAddress(
    IN PCHAR search,
    IN BOOL load,
    OUT PBOOL loaded)
{
    PPEB                    peb          = NULL;
    PPEB_LDR_DATA           ldr          = NULL;
    PIMAGE_DOS_HEADER       dos          = NULL;
    PIMAGE_NT_HEADERS       nt           = NULL;
    PLDR_DATA_TABLE_ENTRY   dte          = NULL;
    PIMAGE_EXPORT_DIRECTORY exp          = NULL;
    LPVOID                  addr         = NULL;
    LPVOID                  base         = NULL;
    DWORD                   rva          = 0;
    PCHAR                   name         = NULL;
    CHAR                    dll_name[64] = { 0 };
    DWORD                   i            = 0;
    int                     correct      = -1;

    if (loaded)
        *loaded = FALSE;

    for(i = 0; search[i] != 0 && i < 64; i++)
    {
        dll_name[i] = search[i];
    }
    dll_name[i] = 0;
    // make sure the name ends with '.dll'
    if (dll_name[i-4] != '.')
    {
        dll_name[i++] = '.';
        dll_name[i++] = 'd';
        dll_name[i++] = 'l';
        dll_name[i++] = 'l';
        dll_name[i++] = 0;
    }

    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    ldr = (PPEB_LDR_DATA)peb->Ldr;

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->Reserved2[1];
         correct != 0 && dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY)dte->Reserved1[0])
    {
        base = dte->DllBase;
        dos  = (PIMAGE_DOS_HEADER)base;
        nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
        rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (rva == 0) continue;

        exp  = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
        name = RVA2VA(PCHAR, base, exp->Name);

        correct = _stricmp(dll_name, name);

        if (correct == 0) {
            addr = base;
        }
    }

    //DPRINT("Address of %s: %p", dll_name, addr);

    // if the DLL was not found, load it
    if (addr == NULL && load)
    {
        addr = LoadLibraryA(dll_name);
        DPRINT("Dll not found. Loaded %s via LoadLibrary at 0x%p", dll_name, addr);
        if (loaded)
            *loaded = TRUE;
    }
    return addr;
}
