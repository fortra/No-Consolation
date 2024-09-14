
#include "hwbp.h"
#include "peb.h"

ULONG_PTR set_bits(
    IN ULONG_PTR dw,
    IN int lowBit,
    IN int bits,
    IN ULONG_PTR newValue)
{
    ULONG_PTR mask = (1UL << bits) - 1UL;
    dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
    return dw;
}

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

    ctx->Dr7 = set_bits(ctx->Dr7, 16, 16, 0);
    ctx->Dr7 = set_bits(ctx->Dr7, (index * 2), 1, 1);

    return TRUE;
}

VOID clear_breakpoint(
    IN CONTEXT* ctx,
    IN DWORD index)
{
    // Clear the releveant hardware breakpoint
    switch (index)
    {
        case 0:
            ctx->Dr0 = 0;
            break;
        case 1:
            ctx->Dr1 = 0;
            break;
        case 2:
            ctx->Dr2 = 0;
            break;
        case 3:
            ctx->Dr3 = 0;
            break;
    }

    ctx->Dr7 = set_bits(ctx->Dr7, (index * 2), 1, 0);
    ctx->Dr6 = 0;
    ctx->EFlags = 0;
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
    if (!RtlAddVectoredExceptionHandler)
    {
        api_not_found("RtlAddVectoredExceptionHandler");
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

VOID unset_hwbp(
    IN HANDLE hThread,
    IN UINT32 index)
{
    NTSTATUS status    = STATUS_UNSUCCESSFUL;
    CONTEXT  threadCtx = { 0 };

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_ALL;

    status = NtGetContextThread(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtGetContextThread", status);
        goto cleanup;
    }

    clear_breakpoint(&threadCtx, index);

    status = NtSetContextThread(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtSetContextThread", status);
        goto cleanup;
    }

cleanup:
    return;
}
