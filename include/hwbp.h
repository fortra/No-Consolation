#pragma once

#include <windows.h>

#define STATUS_UNSUCCESSFUL 0xC0000001

// debug register go from 0 to 3
#define NT_DEVICE_IO_CONTROL_FILE_INDEX 0
#define CREATE_FILE_INDEX               1

// hwbp related macros, simplify x64/x86 support

typedef LONG (CALLBACK* exception_callback)(PEXCEPTION_POINTERS);

#ifdef _WIN64
#define EXCEPTION_CODE(e) (e->ExceptionRecord->ExceptionCode)
#define EXCEPTION_CURRENT_IP(e) ((PVOID)e->ContextRecord->Rip)
#define EXCEPTION_SET_IP( e, p ) e->ContextRecord->Rip = p
#define EXCEPTION_SET_RET( e, r ) e->ContextRecord->Rax = r
#define EXCEPTION_RESUME( e ) e->ContextRecord->EFlags = ( 1 << 16 )
#define EXCEPTION_GET_RET( e ) *( PVOID* ) ( e->ContextRecord->Rsp )
#define EXCEPTION_ADJ_STACK( e, i ) e->ContextRecord->Rsp += i
#define EXCEPTION_ARG_1( e ) ( e->ContextRecord->Rcx )
#define EXCEPTION_ARG_2( e ) ( e->ContextRecord->Rdx )
#else
#define EXCEPTION_CODE( e ) (e->ExceptionRecord->ExceptionCode)
#define EXCEPTION_CURRENT_IP( e ) ((PVOID)e->ContextRecord->Eip)
#define EXCEPTION_SET_IP( e, p ) e->ContextRecord->Eip = p
#define EXCEPTION_SET_RET( e, r ) e->ContextRecord->Eax = r
#define EXCEPTION_RESUME( e ) e->ContextRecord->EFlags = ( 1 << 16 )
#define EXCEPTION_GET_RET( e ) *( PVOID* ) ( e->ContextRecord->Esp )
#define EXCEPTION_ADJ_STACK( e, i ) e->ContextRecord->Esp += i
#define EXCEPTION_ARG_1( e ) *(PVOID*)(e->ContextRecord->Esp + sizeof(PVOID))
#define EXCEPTION_ARG_2( e ) *(PVOID*)(e->ContextRecord->Esp + sizeof(PVOID)*2)
#endif

ULONG_PTR set_bits(
    ULONG_PTR dw,
    int lowBit,
    int bits,
    ULONG_PTR newValue);

VOID clear_breakpoint(
    IN CONTEXT* ctx,
    IN DWORD index);

BOOL enable_breakpoint(
    OUT CONTEXT* ctx,
    IN PVOID address,
    IN int index);

BOOL set_hwbp(
    IN HANDLE hThread,
    IN PVOID address,
    IN exception_callback hwbp_handler,
    IN UINT32 index,
    OUT PHANDLE phHwBpHandler);

VOID remove_hwbp_handler(
    IN HANDLE hHwBpHandler);
