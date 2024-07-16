
#include "console.h"

/*
 * This is simply in case the operator 100% needs a real console for whatever reason
 */
BOOL allocate_console(
    IN PLOADED_PE_INFO peinfo)
{
    if (!peinfo->alloc_console)
        return TRUE;

    DPRINT("allocate_console");

    /*
     * if a console is already allocated, there is no need to allocate one
     */
    if (get_console_handle())
    {
        DPRINT("A console is already allocated, skipping")
        return TRUE;
    }

    BOOL ( WINAPI *AllocConsole ) ( VOID )     = xGetProcAddress(xGetLibAddress("kernel32", TRUE, NULL), "AllocConsole", 0);
    HWND ( WINAPI *GetConsoleWindow ) ( VOID ) = xGetProcAddress(xGetLibAddress("kernel32", TRUE, NULL), "GetConsoleWindow", 0);
    BOOL ( WINAPI *ShowWindow ) ( HWND, int )  = xGetProcAddress(xGetLibAddress("user32", TRUE, NULL),   "ShowWindow", 0);

    if (!AllocConsole)
    {
        api_not_found("AllocConsole");
        return FALSE;
    }

    if (!AllocConsole())
    {
        function_failed("AllocConsole");
        //continue anyways...
    }

    if (!ShowWindow)
    {
        api_not_found("ShowWindow");
        return TRUE;
    }

    if (!GetConsoleWindow)
    {
        api_not_found("GetConsoleWindow");
        return TRUE;
    }

    if (!ShowWindow(GetConsoleWindow(), SW_HIDE))
    {
        function_failed("ShowWindow");
        //continue anyways...
    }

    return TRUE;
}

/*
 * for MinGW binaries, replace the _file attribute of stdout and stderr
 * with the file descriptor of the anonymous pipe
 */
BOOL redirect_std_out_err_for_mingw(
    IN PLOADED_PE_INFO peinfo)
{
    FILE* file = NULL;

    DPRINT("redirect_std_out_err_for_mingw");

    /*
     * if the PE did not load msvcrt.dll, we can skip this step
     */
    if (!peinfo->loaded_msvcrt)
    {
        DPRINT("PE didn't load msvcrt.dll, skipping");
        return TRUE;
    }

    int   ( WINAPI *msvcrt_open_osfhandle ) ( intptr_t, int ) = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "_open_osfhandle", 0);
    FILE* ( WINAPI *msvcrt__iob_func ) ( VOID )               = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "__iob_func", 0);

    if (!msvcrt_open_osfhandle || !msvcrt__iob_func)
    {
        api_not_found("MSVCRT$_open_osfhandle");
        api_not_found("MSVCRT$__iob_func");
        return FALSE;
    }

    if (!peinfo->Handles->fo_msvc)
    {
        // convert the pipe handle into a file descriptor
        peinfo->Handles->fo_msvc = msvcrt_open_osfhandle((intptr_t)peinfo->Handles->hWrite, _O_WRONLY);
        if (peinfo->Handles->fo_msvc == -1)
        {
            peinfo->Handles->fo_msvc = 0;
            function_failed("MSVCRT$_open_osfhandle");
            return FALSE;
        }
    }

    // stdout
    file = &msvcrt__iob_func()[1];

    if (file->_file == 1)
    {
        /*
         * The stdout FILE seems to be initialized
         * modifying it can make the program hang
         */

        DPRINT_ERR("stdout is initialized, skipping");
    }
    else
    {
        // save the original state of stdout
        peinfo->original_msvc_stdout = intAlloc(sizeof(FILE));
        memcpy(peinfo->original_msvc_stdout, file, sizeof(FILE));
        peinfo->msvc_stdout = file;

        // modify stdout
        memset(file, 0, sizeof(FILE));
        file->_flag = _IOWRT | _IONBF;
        file->_file = peinfo->Handles->fo_msvc;

        peinfo->modified_msvc_stdout = TRUE;
    }

    // stderr
    file = &msvcrt__iob_func()[2];

    if (file->_file == 2)
    {
        /*
         * The stderr FILE seems to be initialized
         * modifying it can make the program hang
         */

        DPRINT_ERR("stderr is initialized, skipping");
    }
    else
    {
        // save the original state of stderr
        peinfo->original_msvc_stderr = intAlloc(sizeof(FILE));
        memcpy(peinfo->original_msvc_stderr, file, sizeof(FILE));
        peinfo->msvc_stderr = file;

        // modify stderr
        memset(file, 0, sizeof(FILE));
        file->_flag = _IOWRT | _IONBF;
        file->_file = peinfo->Handles->fo_msvc;

        peinfo->modified_msvc_stderr = TRUE;
    }

    return TRUE;
}

/*
 * for MSVC binaries, replace the _file attribute of stdout and stderr
 * with the file descriptor of the anonymous pipe
 */
BOOL redirect_std_out_err_for_msvc(
    IN PLOADED_PE_INFO peinfo)
{
    PUCRTBASE_FILE file = NULL;

    DPRINT("redirect_std_out_err_for_msvc");

    /*
     * if the PE did not load ucrtbase.dll, we can skip this step
     */
    if (!peinfo->loaded_ucrtbase)
    {
        DPRINT("PE didn't load ucrtbase.dll, skipping");
        return TRUE;
    }

    int            ( WINAPI *ucrtbase_open_osfhandle ) ( intptr_t, int ) = xGetProcAddress(xGetLibAddress("ucrtbase", TRUE, NULL), "_open_osfhandle", 0);
    PUCRTBASE_FILE ( WINAPI *ucrtbase__acrt_iob_func ) ( int )           = xGetProcAddress(xGetLibAddress("ucrtbase", TRUE, NULL), "__acrt_iob_func", 0);

    if (!ucrtbase_open_osfhandle || !ucrtbase__acrt_iob_func)
    {
        api_not_found("UCRTBASE$_open_osfhandle");
        api_not_found("UCRTBASE$__acrt_iob_func");
        return FALSE;
    }

    if (!peinfo->Handles->fo_ucrtbase)
    {
        // convert the pipe handle into a file descriptor (using the ucrtbase version of _open_osfhandle)
        peinfo->Handles->fo_ucrtbase = ucrtbase_open_osfhandle((intptr_t)peinfo->Handles->hWrite, _O_WRONLY);
        if (peinfo->Handles->fo_ucrtbase == -1)
        {
            peinfo->Handles->fo_ucrtbase = 0;
            function_failed("UCRTBASE$_open_osfhandle");
            return FALSE;
        }
    }

    // stdout
    file = ucrtbase__acrt_iob_func(1);

    if (file->_file == 1)
    {
        /*
         * The stdout FILE seems to be initialized
         * modifying it can make the program hang
         */

        DPRINT_ERR("stdout is initialized, skipping");
    }
    else
    {
        // save the original state of stdout
        peinfo->original_ucrtbase_stdout = intAlloc(sizeof(UCRTBASE_FILE));
        memcpy(peinfo->original_ucrtbase_stdout, file, sizeof(UCRTBASE_FILE));
        peinfo->ucrtbase_stdout = file;

        // modify stdout
        memset(file, 0, sizeof(UCRTBASE_FILE));
        file->_flags = 0x2000 | 0x400 | 0x2;
        file->_file  = peinfo->Handles->fo_ucrtbase;
        file->_lock.LockCount = -1;

        peinfo->modified_ucrtbase_stdout = TRUE;
    }

    // stderr
    file = ucrtbase__acrt_iob_func(2);

    if (file->_file == 2)
    {
        /*
         * The stderr FILE seems to be initialized
         * modifying it can make the program hang
         */

        DPRINT_ERR("stderr is initialized, skipping");
    }
    else
    {
        // save the original state of stderr
        peinfo->original_ucrtbase_stderr = intAlloc(sizeof(UCRTBASE_FILE));
        memcpy(peinfo->original_ucrtbase_stderr, file, sizeof(UCRTBASE_FILE));
        peinfo->ucrtbase_stderr = file;

        // modify stderr
        memset(file, 0, sizeof(UCRTBASE_FILE));
        file->_flags = 0x2000 | 0x400 | 0x2;
        file->_file  = peinfo->Handles->fo_ucrtbase;
        file->_lock.LockCount = -1;

        peinfo->modified_ucrtbase_stderr = TRUE;
    }

    return TRUE;
}

PVOID parse_free_console(
    IN PBYTE Addr)
{
    UINT32 Offset                 = 0;
#ifdef _WIN64
    PVOID  Rip                    = NULL;
#endif
    PVOID  ConsoleConnectionState = NULL;
    PBYTE  bytes_to_match         = (PBYTE)"\x80\x3d";

    if (!Addr)
    {
        api_not_found("FreeConsole");
        return NULL;
    }

    /*
     * KERNELBASE$FreeConsole:
     *  ...
     *  80 3d a2        cmp        byte ptr [rip+0x1992a2], 0x0
     *  92 19 00 00
     */

    if (!find_pattern(Addr, 0x30, bytes_to_match, "xx", (PVOID*)&Addr))
    {
        DPRINT("Pattern not found in FreeConsole");
        return NULL;
    }

#ifdef _WIN64
    // address of the next instruction
    Rip  = RVA2VA(PVOID, Addr, 7);
#endif

    // skip over 0x80 0x3d
    Addr++;
    Addr++;

    // read the offset
    Offset = *((PUINT32)Addr);

#ifdef _WIN64
    // the reference is RIP-releative
    Addr = RVA2VA(PVOID, Rip, Offset);
#else
    Addr = (PVOID)Offset;
#endif

    // we have a reference to IsConnected, get the address of the base structure
    ConsoleConnectionState = CONTAINING_RECORD(Addr, CONSOLE_CONNECTION_STATE, IsConnected);
    DPRINT("ConsoleConnectionState: 0x%p", ConsoleConnectionState);

    return ConsoleConnectionState;
}

PVOID parse_base_get_console_reference(
    IN PBYTE Addr)
{
#ifdef _WIN64
    UINT32 Offset                 = 0;
#endif
    PVOID  Rip                    = NULL;
    PVOID  ConsoleReference       = NULL;
    PVOID  ConsoleConnectionState = NULL;

    if (!Addr)
    {
        api_not_found("BaseGetConsoleReference");
        return NULL;
    }

    HANDLE (WINAPI *BaseGetConsoleReference) (void) = (PVOID)Addr;

#ifdef _WIN64
    /*
     * KERNELBASE$BaseGetConsoleReference:
     *  48 8b 05 f9 94 19 00    mov    rax,QWORD PTR [rip+0x1994f9]
     *  c3                      ret
     */

    // address of the 'ret' instruction
    Rip  = RVA2VA(PVOID, Addr, 7);

    if (*Addr != 0x48)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    Addr++;

    if (*Addr != 0x8b)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    Addr++;

    if (*Addr != 0x05)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    Addr++;

    Offset = *((PUINT32)Addr);

    Addr += sizeof(UINT32);

    if (*Addr != 0xc3)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    // the reference is RIP-releative
    ConsoleReference = RVA2VA(PVOID, Rip, Offset);
#else
    /*
     * KERNELBASE$BaseGetConsoleReference:
     *  101bf7f0 a1 c8 47 1e 10  mov        eax,[DAT_101e47c8]
     *  101bf7f5 c3              ret
     */

    // address of the 'ret' instruction
    Rip  = RVA2VA(PVOID, Addr, 5);

    if (*Addr != 0xa1)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    Addr++;

    if (*(PBYTE)Rip != 0xc3)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    ConsoleReference = (PVOID)*((PUINT32)Addr);
#endif

    // make sure we got the address of the ConsoleReference right
    if (BaseGetConsoleReference() != *(PHANDLE)ConsoleReference)
    {
        DPRINT_ERR("failed to parse BaseGetConsoleReference");
        return NULL;
    }

    // get the base of the struct from the address of the attribute
    ConsoleConnectionState = CONTAINING_RECORD(ConsoleReference, CONSOLE_CONNECTION_STATE, ConsoleReference);
    DPRINT("ConsoleConnectionState: 0x%p", ConsoleConnectionState);

    return ConsoleConnectionState;
}

/*
 * In order to find the address of 'ConsoleConnectionState', we parse BaseGetConsoleReference
 * which is a very short function that references a field in that structure
 */
PVOID get_address_of_console_connection_state(VOID)
{
    PBYTE                 Addr                   = NULL;
    PVOID                 ConsoleConnectionState = NULL;
    PVOID                 KernelBase             = NULL;
    PIMAGE_DOS_HEADER     dos                    = NULL;
    PIMAGE_NT_HEADERS     nt                     = NULL;
    PIMAGE_SECTION_HEADER sh                     = NULL;
    LPSTR                 data                   = NULL;
    PVOID                 DataBase               = NULL;
    UINT32                DataSize               = 0;
    PMEMORY_STRUCTS       mem_structs            = NULL;

    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->console_connection_state)
        return mem_structs->console_connection_state;

    /*
     * If exported, we parse kernelbase!BaseGetConsoleReference.
     * If not, we parse kernelbase!FreeConsole which is a bit more complex
     */
    if (!ConsoleConnectionState)
    {
        Addr = xGetProcAddress(xGetLibAddress("KernelBase", TRUE, NULL), "BaseGetConsoleReference", 0);
        ConsoleConnectionState = parse_base_get_console_reference(Addr);
    }

    if (!ConsoleConnectionState)
    {
        Addr = xGetProcAddress(xGetLibAddress("KernelBase", TRUE, NULL), "FreeConsole", 0);
        ConsoleConnectionState = parse_free_console(Addr);
    }

    if (!ConsoleConnectionState)
    {
        DPRINT("Failed to get address of ConsoleConnectionState");
        return NULL;
    }

    /*
     * as a sanity check, we verify that the resulting pointer is on the .data section of KernalBase
     */

    KernelBase = xGetLibAddress("kernelbase", TRUE, NULL);
    if (!KernelBase)
    {
        api_not_found("KernelBase.dll");
        return NULL;
    }

    dos  = (PIMAGE_DOS_HEADER)KernelBase;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);
    sh   = RVA2VA(PIMAGE_SECTION_HEADER, &nt->OptionalHeader, nt->FileHeader.SizeOfOptionalHeader);
    data = ".data";

    // locate the .data segment
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if(*(PDWORD)sh[i].Name == *(PDWORD)data)
        {
            DataBase = RVA2VA(PVOID, KernelBase, sh[i].VirtualAddress);
            DataSize = sh[i].Misc.VirtualSize;
            break;
        }
    }

    if (!DataBase || !DataSize)
    {
        DPRINT_ERR("failed to get range of .data section for KernelBase");
        return NULL;
    }

    if ((ULONG_PTR)DataBase > (ULONG_PTR)ConsoleConnectionState ||
        (ULONG_PTR)DataBase + DataSize < (ULONG_PTR)ConsoleConnectionState)
    {
        DPRINT_ERR("ConsoleConnectionState is not in the .data section");
        return NULL;
    }

    mem_structs->console_connection_state = ConsoleConnectionState;

    return ConsoleConnectionState;
}

/*
 * For cmd, we need to trick BasepCreateProcessParameters into setting
 * the ConsoleHandle for child processes to -1
 * to do this, we can:
 * 1) set our ConsoleReference to -1
 * 2) set our ConsoleReference to NULL and our ConsoleHandle to -1
 * I prefer 1) because it allows us to set the ConsoleHandle to
 * whatever we like, which comes in handy when dealing with PowerShell
 */
BOOL redirect_std_out_err_for_cmd(
    IN PLOADED_PE_INFO peinfo)
{
    PCONSOLE_CONNECTION_STATE ConsoleConnectionState = NULL;

    DPRINT("redirect_std_out_err_for_cmd");

    ConsoleConnectionState = get_address_of_console_connection_state();
    if (!ConsoleConnectionState)
        return FALSE;

    // save the original value of the ConsoleReference
    peinfo->original_console_reference = ConsoleConnectionState->ConsoleReference;
    peinfo->console_reference_addr     = &ConsoleConnectionState->ConsoleReference;

    // set the ConsoleReference to -1
    ConsoleConnectionState->ConsoleReference = (HANDLE)(ULONG_PTR)(-1);
    peinfo->modified_console_reference = TRUE;

    return TRUE;
}

/*
 * when running PowerShell, this function will simulate a successful call to NtDeviceIoControlFile
 */
NTSTATUS NTAPI MyNtDeviceIoControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event,
    IN PIO_APC_ROUTINE  ApcRoutine,
    IN PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength)
{
    PUINT32 ConsoleOutputCP = NULL;
    HANDLE  hConsoleHandle  = NULL;
    LPDWORD lpMode          = NULL;
    LPWSTR  lpConsoleTitle  = NULL;

    if (IoStatusBlock)
    {
        IoStatusBlock->Status = STATUS_SUCCESS;
    }

    PCONSOLE_CP ConsoleCpBuffer = (PCONSOLE_CP)InputBuffer;

    if (IoControlCode == 0x500016 && ConsoleCpBuffer && ConsoleCpBuffer->InputType)
    {
        if (ConsoleCpBuffer->InputType->Id1 == 0x1000000 &&
            ConsoleCpBuffer->InputType->Id2 == 0x8)
        {
            DPRINT("spoofing GetConsoleOutputCP");

            ConsoleOutputCP = ConsoleCpBuffer->OutputPtr;
            *ConsoleOutputCP = 437;

            return STATUS_SUCCESS;
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x3000004 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x54)
        {
            DPRINT("spoofing GetCurrentConsoleFontEx");

            return STATUS_SUCCESS;
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x1000001 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x4)
        {
            DPRINT("spoofing GetConsoleMode");

            hConsoleHandle = ConsoleCpBuffer->InputValue;
            lpMode         = ConsoleCpBuffer->OutputPtr;

            if (hConsoleHandle == get_std_out_handle())
            {
                /*
                 * calling GetConsoleMode on the fake 'StandardOutput' has to fail
                 */
                *lpMode = 0x0;
                return STATUS_INVALID_HANDLE;
            }
            else if (hConsoleHandle == get_std_in_handle())
            {
                /*
                 * calling GetConsoleMode on 'StandardInput' has to succeed with 0x1f7
                 */
                *lpMode = 0x1f7;
                return STATUS_SUCCESS;
            }
            else
            {
                /*
                 * on the other handles, GetConsoleMode on 'StandardInput' has to succeed with 0x3
                 */
                *lpMode = 0x3;
                return STATUS_SUCCESS;
            }
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x2000007 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x5c)
        {
            DPRINT("spoofing GetConsoleScreenBufferInfo");

            return STATUS_SUCCESS;
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x1000002 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x4)
        {
            DPRINT("spoofing SetConsoleMode");

            return STATUS_SUCCESS;
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x2000014 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x80)
        {
            DPRINT("spoofing GetConsoleTitleW");

            lpConsoleTitle = ConsoleCpBuffer->OutputPtr;
            lpConsoleTitle[0x0] = L'N';
            lpConsoleTitle[0x1] = L'o';
            lpConsoleTitle[0x2] = L'C';
            lpConsoleTitle[0x3] = L'o';
            lpConsoleTitle[0x4] = L'n';
            lpConsoleTitle[0x5] = L's';
            lpConsoleTitle[0x6] = L'o';
            lpConsoleTitle[0x7] = L'l';
            lpConsoleTitle[0x8] = L'a';
            lpConsoleTitle[0x9] = L't';
            lpConsoleTitle[0xa] = L'i';
            lpConsoleTitle[0xb] = L'o';
            lpConsoleTitle[0xc] = L'n';
            lpConsoleTitle[0xd] = L'\0';

            return STATUS_SUCCESS;
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x2000015 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x10)
        {
            DPRINT("spoofing SetConsoleTitleW");

            return STATUS_SUCCESS;
        }
        else if (ConsoleCpBuffer->InputType->Id1 == 0x1000008 &&
                 ConsoleCpBuffer->InputType->Id2 == 0x2)
        {
            DPRINT("spoofing SetTEBLangID");

            return STATUS_SUCCESS;
        }
    }

    if (ConsoleCpBuffer && ConsoleCpBuffer->InputType)
    {
        DPRINT_ERR("failed to understand message, Id1: %x, Id2: %d", ConsoleCpBuffer->InputType->Id1, ConsoleCpBuffer->InputType->Id2);
    }
    else
    {
        DPRINT_ERR("failed to understand message");
    }

    return STATUS_SUCCESS;
}

LONG CALLBACK NtDeviceIoControlFileHandler(
    PEXCEPTION_POINTERS exception)
{
    PVOID Addr = NULL;

    if (EXCEPTION_CODE( exception ) == STATUS_SINGLE_STEP)
    {
        // check if the exception address is NtDeviceIoControlFile
        Addr = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "NtDeviceIoControlFile", 0);
        if (EXCEPTION_CURRENT_IP( exception ) == Addr)
        {
            // check the first parameter is the ConsoleHandle
            if ((HANDLE)EXCEPTION_ARG_1( exception ) == get_console_handle())
            {
                // redirect execution to the fake NtDeviceIoControlFile
                EXCEPTION_SET_IP( exception, (ULONG_PTR)MyNtDeviceIoControlFile );

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                // if the first parameter is not the ConsoleHandle, continue executing normally
                EXCEPTION_RESUME( exception );
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG CALLBACK CreateFileWHandler(
    PEXCEPTION_POINTERS exception)
{
    PVOID  Addr     = NULL;
    LPWSTR FileName = NULL;
    PVOID  Return   = NULL;

    if (EXCEPTION_CODE( exception ) == STATUS_SINGLE_STEP)
    {
        // check if the exception address is CreateFileW
        Addr = xGetProcAddress(xGetLibAddress("kernelbase", TRUE, NULL), "CreateFileW", 0);
        if (EXCEPTION_CURRENT_IP( exception ) == Addr)
        {
            // check the first parameter is CONOUT$
            FileName = (LPWSTR)EXCEPTION_ARG_1( exception );
            if (FileName &&
                FileName[0] == L'C' &&
                FileName[1] == L'O' &&
                FileName[2] == L'N' &&
                FileName[3] == L'O' &&
                FileName[4] == L'U' &&
                FileName[5] == L'T' &&
                FileName[6] == L'$' &&
                FileName[7] == L'\0')
            {
                DPRINT("Spoofing CreateFileW(\"CONOUT$\", ...)");

                // set a fake handle as return value, anything but -1 will do
                EXCEPTION_SET_RET( exception, 0x123 );

                // return
                Return = EXCEPTION_GET_RET( exception );
                EXCEPTION_ADJ_STACK( exception, sizeof( PVOID ) );
                EXCEPTION_SET_IP( exception, (ULONG_PTR)Return );

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                // if the first parameter is not CONOUT$, continue executing normally
                EXCEPTION_RESUME( exception );
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * For PowerShell, we spoof a console by hooking
 * NtDeviceIoControlFile and CreateFileW using hardware breakpoints
 */
BOOL redirect_std_out_err_for_ps(
    IN PLOADED_PE_INFO peinfo)
{
    HANDLE hFakeConsoleHandle        = NULL;
    PVOID  AddrNtDeviceIoControlFile = NULL;
    PVOID  AddrCreateFileW           = NULL;

    DPRINT("redirect_std_out_err_for_ps");

    /*
     * if the PE did not load mscoree.dll, we can skip this step
     */
    if (!peinfo->loaded_mscoree)
    {
        DPRINT("PE didn't load mscoree.dll, skipping");
        return TRUE;
    }

    /*
     * if the operator decided to load a console, there is no need to spoof one
     */
    if (peinfo->alloc_console)
    {
        DPRINT("A console will be allocated, skipping")
        return TRUE;
    }

    /*
     * if a console is already allocated, there is no need to spoof one
     */
    if (get_console_handle())
    {
        DPRINT("A console is already allocated, skipping")
        return TRUE;
    }

    AddrNtDeviceIoControlFile = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL),      "NtDeviceIoControlFile", 0);
    AddrCreateFileW           = xGetProcAddress(xGetLibAddress("kernelbase", TRUE, NULL), "CreateFileW", 0);

    if (!AddrNtDeviceIoControlFile)
    {
        api_not_found("NtDeviceIoControlFile");
        return FALSE;
    }

    if (!AddrCreateFileW)
    {
        api_not_found("CreateFileW");
        return FALSE;
    }

    /*
     * set a hardware breakpoint on NtDeviceIoControlFile and CreateFileW
     */

    if (!set_hwbp(
        peinfo->hThread,
        AddrNtDeviceIoControlFile,
        NtDeviceIoControlFileHandler,
        NT_DEVICE_IO_CONTROL_FILE_INDEX,
        &peinfo->hHwBp1))
    {
        DPRINT_ERR("Failed to set HWBP on NTDLL$NtDeviceIoControlFile");
        return FALSE;
    }

    if (!set_hwbp(
        peinfo->hThread,
        AddrCreateFileW,
        CreateFileWHandler,
        CREATE_FILE_INDEX,
        &peinfo->hHwBp2))
    {
        DPRINT_ERR("Failed to set HWBP on KERNELBASE$CreateFileW");
        return FALSE;
    }

    /*
     * set a fake console handle on PEB->ProcessParameters->ConsoleHandle
     */

    int (WINAPI *rand) (void)  = xGetProcAddress(xGetLibAddress("msvcrt", TRUE, NULL), "rand", 0);
    if (!rand)
    {
        api_not_found("rand");
        return FALSE;
    }

    while (!hFakeConsoleHandle || hFakeConsoleHandle == get_std_in_handle())
    {
        hFakeConsoleHandle = (HANDLE)(ULONG_PTR)((rand() & (2047 - 1)) & ~3);
    }

    // save the original console handle
    peinfo->original_console_handle = get_console_handle();

    // set the fake console handle
    set_console_handle(hFakeConsoleHandle);

    peinfo->modified_console_handle = TRUE;

    DPRINT("fake console handle: 0x%x", hFakeConsoleHandle);

    return TRUE;
}

/*
 * Many binaries simply need the standard output and error
 * handles on the PEB->ProcessParameters structure to be overwritten
 * with the write handle from the anonymous pipe
 */
BOOL redirect_std_out_err_generic(
    IN PLOADED_PE_INFO peinfo)
{
    DPRINT("redirect_std_out_err_generic");

    // save the original values of StandardOutput/Error
    peinfo->original_user_params_stdout = get_std_out_handle();
    peinfo->original_user_params_stderr = get_std_err_handle();

    // set the pipe write handle as Stdout
    set_std_out_handle(peinfo->Handles->hWrite);
    peinfo->modified_user_params_stdout = TRUE;

    // set the pipe write handle as Stderr
    set_std_err_handle(peinfo->Handles->hWrite);
    peinfo->modified_user_params_stderr = TRUE;

    return TRUE;
}

/*
 * PowerShell doesn't like the output Pipe handles to change in between executions.
 * Because of this, we only create the anonymous pipe once.
 * To remember the pipe values, we use the Key/Value store from beacon
 */
BOOL recover_handle_info(
    IN PLOADED_PE_INFO peinfo)
{
    // try to recover the handle information from previous runs
    peinfo->Handles = BeaconGetValue(NC_HANDLE_INFO_KEY);

    if (peinfo->Handles)
    {
        DPRINT("Recovered handle information");
    }
    else
    {
        // this is the first run, create a new anonymous pipe
        DPRINT("Creating anonymous pipe");

        // allocate the HANDLE_INFO structure
        peinfo->Handles = intAlloc(sizeof(HANDLE_INFO));

        // create the pipe
        SECURITY_ATTRIBUTES sao = { sizeof(sao), NULL, TRUE };
        if (!CreatePipe(&peinfo->Handles->hRead, &peinfo->Handles->hWrite, &sao, 0))
        {
            function_failed("CreatePipe");
            return FALSE;
        }

        // save the handle information for future executions
        if (!BeaconAddValue(NC_HANDLE_INFO_KEY, peinfo->Handles))
        {
            function_failed("BeaconAddValue");
            return FALSE;
        }
    }

    return TRUE;
}

BOOL redirect_std_out_err(
    IN PLOADED_PE_INFO peinfo)
{
    if (peinfo->nooutput)
    {
        return TRUE;
    }

    if (!recover_handle_info(peinfo))
    {
        return FALSE;
    }

    /*
     * this works for:
     * - MinGW cross-compiled binaries
     * - clang cross-compiled binaries
     */
    if (!redirect_std_out_err_for_mingw(peinfo))
    {
        return FALSE;
    }

    /*
     * this works for:
     * - MSVC binaries compiled with link.exe
     */
    if (!redirect_std_out_err_for_msvc(peinfo))
    {
        return FALSE;
    }

    /*
     * this works for:
     * - CMD run with /c
     * - other binaries that call CreateProcessW
     */
    if (!redirect_std_out_err_for_cmd(peinfo))
    {
        return FALSE;
    }

    /*
     * this works for:
     * - PowerShell
     */
    if (!redirect_std_out_err_for_ps(peinfo))
    {
        return FALSE;
    }

    /*
     * This is disabled by default
     */
    if (!allocate_console(peinfo))
    {
        return FALSE;
    }

    /*
     * this works for:
     * - handle.exe
     * - PsExec.exe
     * - several other
     */
    if (!redirect_std_out_err_generic(peinfo))
    {
        return FALSE;
    }

    return TRUE;
}
