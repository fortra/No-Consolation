#pragma once

#include <windows.h>

#include "entry.h"
#include "bofdefs.h"
#include "hwbp.h"
#include "utils.h"

#define STATUS_SUCCESS        0x00000000
//#define STATUS_INVALID_HANDLE 0xc0000008

// Structures invovled in parsing PEB

#define RTL_MAX_DRIVE_LETTERS 32

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT                  Flags;
    USHORT                  Length;
    ULONG                   TimeStamp;
    UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _uRTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData; //8+
    ULONG ProcessGroupId;
    // ULONG LoaderThreads;
} uRTL_USER_PROCESS_PARAMETERS, * uPRTL_USER_PROCESS_PARAMETERS;

// fd flag
#define _O_WRONLY 0x0001

// internal structure used by NtDeviceIoControlFile
typedef struct _CONSOLE_CP_INPUT {
    UINT32 Id1;
    UINT32 Id2;
} CONSOLE_CP_INPUT, * PCONSOLE_CP_INPUT;

// internal structure used by NtDeviceIoControlFile
typedef struct _CONSOLE_CP {
    PVOID InputValue;
    UINT32 unknown2;
    UINT32 unknown3;
    UINT32 InputSize;
    PCONSOLE_CP_INPUT InputType;
    UINT32 OutputSize;
    PVOID OutputPtr;
} CONSOLE_CP, * PCONSOLE_CP;

// internal structure used by AllocConsole/BasepCreateProcessParameters
typedef struct _CONSOLE_CONNECTION_STATE {
/*0x00 0x01*/ BYTE   Flags;
/*0x08 0x08*/ HANDLE ConsoleHandle;
/*0x10 0x08*/ HANDLE ConsoleReference;
/*0x18 0x08*/ HANDLE StandardInput;
/*0x20 0x08*/ HANDLE StandardOutput;
/*0x28 0x08*/ HANDLE StandardError;
/*0x30 0x01*/ BYTE   IsConnected;
} CONSOLE_CONNECTION_STATE, * PCONSOLE_CONNECTION_STATE;

// internal structure used by ucrtbase.dll
typedef struct _UCRTBASE_FILE {
/*0x00 0x08*/ PVOID  _ptr;
/*0x08 0x08*/ PVOID  _base;
/*0x10 0x04*/ UINT32 _cnt;
/*0x14 0x04*/ UINT32 _flags;
/*0x18 0x04*/ UINT32 _file;
/*0x1c 0x04*/ UINT32 _bufsiz;
/*0x20 0x08*/ PVOID  _charbuf;
/*0x28 0x08*/ LPSTR  _tmpfname;
/*0x30 0x28*/ CRITICAL_SECTION _lock;
} UCRTBASE_FILE, * PUCRTBASE_FILE;

BOOL redirect_std_out_err(
    IN PLOADED_PE_INFO peinfo);
