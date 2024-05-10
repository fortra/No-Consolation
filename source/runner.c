
#include "runner.h"

BOOL set_thread_context(
    IN HANDLE hThread,
    IN PVOID Rip,
    IN PVOID Param1,
    IN PVOID Param2,
    IN PVOID Param3)
{
    CONTEXT  threadCtx = { 0 };
    NTSTATUS status    = STATUS_UNSUCCESSFUL;
    PVOID    Ret       = NULL;

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_ALL;

    NTSTATUS (NTAPI* NtGetContextThread)(HANDLE, PCONTEXT) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "NtGetContextThread", 0);
    NTSTATUS (NTAPI* NtSetContextThread)(HANDLE, PCONTEXT) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "NtSetContextThread", 0);

    if (!NtGetContextThread)
    {
        api_not_found("NtGetContextThread");
        return FALSE;
    }

    if (!NtSetContextThread)
    {
        api_not_found("NtSetContextThread");
        return FALSE;
    }

    status = NtGetContextThread(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetContextThread", status);
        return FALSE;
    }

    CONTEXT_SET_IP( threadCtx, Rip );
    CONTEXT_SET_ARG1( threadCtx, Param1 );
    CONTEXT_SET_ARG2( threadCtx, Param2 );
    CONTEXT_SET_ARG3( threadCtx, Param3 );

#ifdef _M_IX86
    // on x86, some DLLs crash at RtlExitUserThread if we don't add some extra space
    CONTEXT_ADD_STACK_SPACE( threadCtx, sizeof(PVOID) * 5 );
#endif

    /*
     * for DLLs, the return address is usually NULL
     * when this is the case, we simply set it to RtlExitUserThread
     */
    if (CONTEXT_GET_RET( threadCtx ) == NULL)
    {
        DPRINT("Setting the return address to RtlExitUserThread");
        Ret = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlExitUserThread", 0);
        CONTEXT_SET_RET( threadCtx, Ret);
    }

    status = NtSetContextThread(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetContextThread", status);
        return FALSE;
    }

    return TRUE;
}

BOOL prepare_thread(
    IN PLOADED_PE_INFO peinfo)
{
    DllMain_t DllMain = NULL;

    if (peinfo->is_dll)
    {
        if (peinfo->method)
        {
            /*
             * The operator specified a method to run.
             * Before we run it, we must first call DllMain,
             * we do that with our current thread (meaning, no hwbp)
             */

            DPRINT("Executing DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)");

            DllMain = peinfo->DllMain;
            DllMain(peinfo->pe_base, DLL_PROCESS_ATTACH, NULL);

            DPRINT("Invoking %s at 0x%p", peinfo->method, peinfo->DllParam);

            if (peinfo->cmdwline || peinfo->cmdline)
            {
                if (peinfo->use_unicode)
                {
                    if (!set_thread_context(peinfo->hThread, peinfo->DllParam, (PVOID)peinfo->cmdwline, NULL, NULL))
                    {
                        return FALSE;
                    }
                }
                else
                {
                    if (!set_thread_context(peinfo->hThread, peinfo->DllParam, (PVOID)peinfo->cmdline, NULL, NULL))
                    {
                        return FALSE;
                    }
                }
            }
            else
            {
                if (!set_thread_context(peinfo->hThread, peinfo->DllParam, NULL, NULL, NULL))
                {
                    return FALSE;
                }
            }
        }
        else
        {
            DPRINT("Invoking DllMain at 0x%p", peinfo->DllMain);

            if (!set_thread_context(peinfo->hThread, peinfo->DllMain, peinfo->pe_base, (PVOID)DLL_PROCESS_ATTACH, NULL))
            {
                return FALSE;
            }
        }
    }
    else
    {
        DPRINT("Executing entrypoint of PE: 0x%p", peinfo->EntryPoint);

        if (!set_thread_context(peinfo->hThread, peinfo->EntryPoint, NULL, NULL, NULL))
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL resume_thread(
    IN PLOADED_PE_INFO peinfo)
{
    DWORD (WINAPI* ResumeThread) (HANDLE) = xGetProcAddress(xGetLibAddress("kernel32", TRUE, NULL), "ResumeThread", 0);
    if (!ResumeThread)
    {
        api_not_found("ResumeThread");
        return FALSE;
    }

    if (ResumeThread(peinfo->hThread) == -1)
    {
        function_failed("ResumeThread");
        return FALSE;
    }

    return TRUE;
}

BOOL read_output(
    IN PLOADED_PE_INFO peinfo,
    OUT PBOOL aborted)
{
    DWORD         output_length   = 0;
    DWORD         event_type      = -1;
    BOOL          thread_finished = FALSE;
    PCHAR         recv_buffer     = NULL;
    BOOL          check_timeout   = peinfo->timeout != 0;
    LARGE_INTEGER frequency       = { 0 };
    LARGE_INTEGER before          = { 0 };
    LARGE_INTEGER after           = { 0 };

    // Get timestamp immediately before running PE for comparison later
    if (check_timeout && !QueryPerformanceFrequency(&frequency))
    {
        function_failed("QueryPerformanceFrequency");
        check_timeout = FALSE;
    }

    if (check_timeout && !QueryPerformanceCounter(&before))
    {
        function_failed("QueryPerformanceCounter");
        check_timeout = FALSE;
    }

    // Allocate buffer to hold output from PE
    if (!peinfo->nooutput)
    {
        recv_buffer = intAlloc(BUFFER_SIZE);
        if (!recv_buffer)
        {
            malloc_failed();
            return FALSE;
        }
    }

    do {
        // Get current time
        if (check_timeout && !QueryPerformanceCounter(&after))
        {
            function_failed("QueryPerformanceCounter");
            check_timeout = FALSE;
        }

        // Check if the timeout was reached
        if (check_timeout && (after.QuadPart - before.QuadPart) > (peinfo->timeout * frequency.QuadPart))
        {
            // Kill thread
            if (peinfo->hThread && !TerminateThread(peinfo->hThread, 0))
            {
                function_failed("TerminateThread");
            }

            if (peinfo->hThread)
                NtClose(peinfo->hThread);
            peinfo->hThread = NULL;

            check_timeout   = FALSE;
            thread_finished = TRUE;

            if (aborted)
                *aborted = TRUE;
        }

        if (!thread_finished && peinfo->hThread)
        {
            // Wait for the thread to terminate
            event_type = WaitForSingleObject(peinfo->hThread, _WAIT_TIMEOUT);

            switch (event_type) {
            case WAIT_ABANDONED:
                break;
            case WAIT_TIMEOUT:
                break;
            case WAIT_FAILED:
                function_failed("WaitForSingleObject");
                break;
            case WAIT_OBJECT_0:
                DPRINT("The thread has finished");
                NtClose(peinfo->hThread);
                peinfo->hThread = NULL;
                check_timeout   = FALSE;
                thread_finished = TRUE;
                break;
            default:
                DPRINT("Unknown event type: %d", event_type);
            }
        }

        if (!peinfo->nooutput)
        {
            // See if/how much data is available to be read from pipe
            if (!PeekNamedPipe(peinfo->Handles->hRead, NULL, 0, NULL, &output_length, NULL))
            {
                function_failed("PeekNamedPipe");
            }

            // If there is data to be read, zero out buffer, read data, and send back to CS
            if (output_length)
            {
                memset(recv_buffer, 0, BUFFER_SIZE);

                if (ReadFile((PVOID)peinfo->Handles->hRead, recv_buffer, BUFFER_SIZE - 1, NULL, NULL))
                {
                    // Send output back
                    PRINT("%s", recv_buffer);
                }
                else
                {
                    function_failed("ReadFile");
                }
            }
        }
    } while (!thread_finished || output_length);

    // Free results buffer
    if (recv_buffer)
    {
        memset(recv_buffer, 0, BUFFER_SIZE);
        intFree(recv_buffer);
    }

    return TRUE;
}

BOOL run_pe(
    IN PLOADED_PE_INFO peinfo)
{
    BOOL      aborted = FALSE;
    DllMain_t DllMain = NULL;

    if (!prepare_thread(peinfo))
    {
        return FALSE;
    }

    if (!resume_thread(peinfo))
    {
        return FALSE;
    }

    if (!read_output(peinfo, &aborted))
    {
        return FALSE;
    }

    if (peinfo->is_dll && !aborted)
    {
        /*
         * The DLL's thread has exited,
         * now we call DllMain with DLL_PROCESS_DETACH.
         * We only do this when the PE exits gracefully
         */

        DPRINT("Executing DllMain(hinstDLL, DLL_PROCESS_DETACH, NULL)");

        DllMain = peinfo->DllMain;
        DllMain(peinfo->pe_base, DLL_PROCESS_DETACH, NULL);
    }

    if (aborted)
    {
        PRINT_ERR("timeout reached");
    }
    else
    {
        PRINT("done");
    }

    return TRUE;
}
