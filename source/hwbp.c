
#include "hwbp.h"
#include "peb.h"

BOOL enable_breakpoint(
    OUT CONTEXT* ctx,
    IN PVOID address,
    IN int index)
{
    switch (index)
    {
        case 0:
            ctx->Dr0 = (ULONG_PTR)address;
            break;
        case 1:
            ctx->Dr1 = (ULONG_PTR)address;
            break;
        case 2:
            ctx->Dr2 = (ULONG_PTR)address;
            break;
        case 3:
            ctx->Dr3 = (ULONG_PTR)address;
            break;
        default:
            DPRINT("Invalid index: %d", index);
            return FALSE;
    }

    ctx->Dr7 &= ~(3ull << (16 + 4 * index));
    ctx->Dr7 &= ~(3ull << (18 + 4 * index));
    ctx->Dr7 |= 1ull << (2 * index);

    return TRUE;
}

BOOL set_hwbp(
    IN HANDLE hThread,
    IN PVOID address,
    IN exception_callback hwbp_handler,
    IN UINT32 index,
    OUT PHANDLE phHwBpHandler)
{
    BOOL     ret_val      = FALSE;
    NTSTATUS status       = STATUS_UNSUCCESSFUL;
    HANDLE   hHwBpHandler = NULL;
    CONTEXT  threadCtx    = { 0 };

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    PVOID (WINAPI* RtlAddVectoredExceptionHandler) (ULONG, exception_callback) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlAddVectoredExceptionHandler", 0);
	NTSTATUS (NTAPI* NtGetContextThread)(HANDLE, PCONTEXT) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "NtGetContextThread", 0);
	NTSTATUS (NTAPI* NtSetContextThread)(HANDLE, PCONTEXT) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "NtSetContextThread", 0);

    if (!RtlAddVectoredExceptionHandler)
    {
        api_not_found("RtlAddVectoredExceptionHandler");
        goto Cleanup;
    }

    if (!NtGetContextThread)
    {
        api_not_found("NtGetContextThread");
        goto Cleanup;
    }

    if (!NtSetContextThread)
    {
        api_not_found("NtSetContextThread");
        goto Cleanup;
    }

    hHwBpHandler = RtlAddVectoredExceptionHandler(1, hwbp_handler);
    if (!hHwBpHandler)
    {
        function_failed("RtlAddVectoredExceptionHandler");
        goto Cleanup;
    }

    status = NtGetContextThread(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetContextThread", status);
        goto Cleanup;
    }

    if (!enable_breakpoint(&threadCtx, address, index))
        goto Cleanup;

    status = NtSetContextThread(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetContextThread", status);
        goto Cleanup;
    }

    if (phHwBpHandler)
        *phHwBpHandler = hHwBpHandler;

    ret_val = TRUE;

Cleanup:
    return ret_val;
}

VOID remove_hwbp_handler(
    IN HANDLE hHwBpHandler)
{
    if (!hHwBpHandler)
        return;

    ULONG (WINAPI* RtlRemoveVectoredExceptionHandler) (PVOID) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlRemoveVectoredExceptionHandler", 0);

    /*
     * Given that the PE thread always dies,
     * we do not need to clear the Dr7 register
     * we simply remove the handler
     */

    if (!RtlRemoveVectoredExceptionHandler)
    {
        api_not_found("RtlRemoveVectoredExceptionHandler");
        return;
    }

    if (!RtlRemoveVectoredExceptionHandler(hHwBpHandler))
    {
        function_failed("RtlRemoveVectoredExceptionHandler");
    }
}
