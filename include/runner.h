#pragma once

#include "bofdefs.h"

#define BUFFER_SIZE 4096
#define _WAIT_TIMEOUT 500

// thread context related macros, simplify x64/x86 support

#ifdef _WIN64
#define CONTEXT_SET_IP( ctx, p ) ctx.Rip = (ULONG_PTR)p
#define CONTEXT_SET_ARG1( ctx, p ) ctx.Rcx = (ULONG_PTR)p
#define CONTEXT_SET_ARG2( ctx, p ) ctx.Rdx = (ULONG_PTR)p
#define CONTEXT_SET_ARG3( ctx, p ) ctx.R8 = (ULONG_PTR)p
#define CONTEXT_GET_RET( ctx ) *(PVOID*)ctx.Rsp
#define CONTEXT_SET_RET( ctx, p ) *(PVOID*)ctx.Rsp = p
#else
#define CONTEXT_SET_IP( ctx, p ) ctx.Eip = (ULONG_PTR)p
#define CONTEXT_SET_ARG1( ctx, p ) *(PVOID*)(ctx.Esp + sizeof(PVOID)) = p
#define CONTEXT_SET_ARG2( ctx, p ) *(PVOID*)(ctx.Esp + sizeof(PVOID) * 2) = p
#define CONTEXT_SET_ARG3( ctx, p ) *(PVOID*)(ctx.Esp + sizeof(PVOID) * 3) = p
#define CONTEXT_GET_RET( ctx ) *(PVOID*)ctx.Esp
#define CONTEXT_SET_RET( ctx, p ) *(PVOID*)ctx.Esp = p
#define CONTEXT_ADD_STACK_SPACE( ctx, p ) ctx.Esp -= p
#endif

BOOL run_pe(
    IN PLOADED_PE_INFO peinfo);
