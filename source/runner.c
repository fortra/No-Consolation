
#include "runner.h"

BOOL exec_entrypoint_inthread(
    IN PVOID EntryPoint,
    IN PVOID Param1,
    IN PVOID Param2,
    IN PVOID Param3)
{
    Entry_t   Entry    = EntryPoint;
    PVOID     Rsp      = NULL;
    PVOID     Rbp      = NULL;
    PEXEC_CTX exec_ctx = NULL;

    // get RSP and RBP
#ifdef _WIN64
    __asm__(
        "mov rax, rsp \n"
        "mov rdx, rbp \n"
        : "=r" (Rbp), // RDX OUT
          "=r" (Rsp)  // RAX OUT
        :
    );
#else
    __asm__(
        "mov eax, esp \n"
        "mov edx, ebp \n"
        : "=r" (Rbp), // EDX OUT
          "=r" (Rbp)  // EAX OUT
        :
    );
#endif

    // save the execution context in the Key/Value store
    exec_ctx = intAlloc(sizeof(EXEC_CTX));
    exec_ctx->Rsp = Rsp;
    exec_ctx->Rbp = Rbp;
    exec_ctx->Rip = &&return_addr;
    exec_ctx->Tid = get_tid();
    BeaconAddValue(NC_EXEC_CTX, exec_ctx);

    // jumping to the entry point... wish me luck!
    Entry(Param1, Param2, Param3);

return_addr:
    DPRINT("Execution context restored"); // :^)

    memset(exec_ctx, 0, sizeof(EXEC_CTX));
    intFree(exec_ctx);
    BeaconRemoveValue(NC_EXEC_CTX);

    return TRUE;
}

BOOL run_pe_inthread(
    IN PLOADED_PE_INFO peinfo)
{
    if (peinfo->is_dll)
    {
        if (peinfo->method)
        {
            DPRINT("Executing %ls!%s", peinfo->pe_wname, peinfo->method);

            if (peinfo->cmdwline || peinfo->cmdline)
            {
                if (peinfo->use_unicode)
                {
                    if (!exec_entrypoint_inthread(peinfo->DllParam, (PVOID)peinfo->cmdwline, NULL, NULL))
                    {
                        return FALSE;
                    }
                }
                else
                {
                    if (!exec_entrypoint_inthread(peinfo->DllParam, (PVOID)peinfo->cmdline, NULL, NULL))
                    {
                        return FALSE;
                    }
                }
            }
            else
            {
                if (!exec_entrypoint_inthread(peinfo->DllParam, NULL, NULL, NULL))
                {
                    return FALSE;
                }
            }
        }
        else
        {
            if (peinfo->DllMain)
            {
                DPRINT("Executing DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)");

                if (!exec_entrypoint_inthread(peinfo->DllMain, peinfo->pe_base, (PVOID)DLL_PROCESS_ATTACH, NULL))
                {
                    return FALSE;
                }
            }
        }
    }
    else
    {
        DPRINT("Executing %ls", peinfo->pe_wname);

        if (!exec_entrypoint_inthread(peinfo->EntryPoint, NULL, NULL, NULL))
        {
            return FALSE;
        }
    }

    return TRUE;
}

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
    if (peinfo->is_dll)
    {
        if (peinfo->method)
        {
            DPRINT("Executing %ls!%s", peinfo->pe_wname, peinfo->method);

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
            if (peinfo->DllMain)
            {
                DPRINT("Executing DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)");

                if (!set_thread_context(peinfo->hThread, peinfo->DllMain, peinfo->pe_base, (PVOID)DLL_PROCESS_ATTACH, NULL))
                {
                    return FALSE;
                }
            }
        }
    }
    else
    {
        DPRINT("Executing %ls", peinfo->pe_wname);

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

BOOL read_output_from_thread(
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

BOOL read_output_inthread(
    IN PLOADED_PE_INFO peinfo)
{
    DWORD output_length = 0;
    PCHAR recv_buffer   = NULL;

    if (peinfo->nooutput)
        return TRUE;

    recv_buffer = intAlloc(BUFFER_SIZE);
    if (!recv_buffer)
    {
        malloc_failed();
        return FALSE;
    }

    do {
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
    } while (output_length);

    // Free results buffer
    memset(recv_buffer, 0, BUFFER_SIZE);
    intFree(recv_buffer);

    return TRUE;
}

BOOL run_pe(
    IN PLOADED_PE_INFO peinfo)
{
    BOOL      aborted = FALSE;
    DllMain_t DllMain = NULL;

    /*
     * If we are supposed to run DllMain,
     * make sure the DLL has an entrypoint
     */
    if (peinfo->is_dll && !peinfo->method && !peinfo->DllMain)
    {
        PRINT("The DLL %ls does not have an entrypoint", peinfo->pe_wname);
        return TRUE;
    }

    if (peinfo->inthread)
    {
        if (!run_pe_inthread(peinfo))
        {
            return FALSE;
        }

        if (!read_output_inthread(peinfo))
        {
            return FALSE;
        }
    }
    else
    {
        if (!prepare_thread(peinfo))
        {
            return FALSE;
        }

        if (!resume_thread(peinfo))
        {
            return FALSE;
        }

        if (!read_output_from_thread(peinfo, &aborted))
        {
            return FALSE;
        }
    }

    if (peinfo->is_dll && peinfo->DllMain && !aborted && !peinfo->dont_unload)
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
