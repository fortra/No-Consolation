#pragma once

#define ARGUMENT_PRESENT(ArgumentPointer) \
  ((CHAR*)((ULONG_PTR)(ArgumentPointer)) != (CHAR*)NULL)

#define MAXUSHORT 65535
#define MAX_USTRING ( sizeof(WCHAR) * (MAXUSHORT/sizeof(WCHAR)) )

#define STATUS_INVALID_BUFFER_SIZE 0xC0000206

PVOID find_ldrp_handle_tls_data(VOID);

PVOID find_ldrp_release_tls_entry(VOID);

VOID insert_tail_list(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry);

VOID unlink_from_list(
    PLIST_ENTRY Entry);

SIZE_T StringLengthA(
    IN LPCSTR String);

PCHAR StringConcatA(
    IN PCHAR String,
    IN PCHAR String2);

VOID myRtlInitUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString);

SIZE_T StringLengthW(
    IN LPCWSTR String);

PCHAR StringCopyA(
    IN PCHAR String1,
    IN PCHAR String2);

SIZE_T WCharStringToCharString(
    IN PCHAR Destination,
    IN PWCHAR Source,
    IN SIZE_T MaximumAllowed);

SIZE_T CharStringToWCharString(
    IN PWCHAR Destination,
    IN PCHAR Source,
    IN SIZE_T MaximumAllowed);

LONG RtlCompareUnicodeString(
    IN PCUNICODE_STRING String1,
    IN PCUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive);

VOID RtlInitEmptyUnicodeString(
    OUT PUNICODE_STRING UnicodeString,
    IN PWCHAR Buffer,
    IN UINT16 BufferSize);

LONG RtlCompareUnicodeStrings(
    IN CONST WCHAR* String1,
    IN SIZE_T Length1,
    IN CONST WCHAR* String2,
    IN SIZE_T Length2,
    IN BOOLEAN CaseInSensitive);

BOOL string_is_included(
    IN PCHAR list_of_strings,
    IN PCHAR string_to_search);

BOOL find_pattern(
    IN PVOID dwAddress,
    IN ULONG32 dwLen,
    IN PBYTE bMask,
    IN PCHAR szMask,
    OUT PVOID* pattern_addr);

BOOL is_pe(
    IN HMODULE hLibrary);

BOOL is_dll(
    IN HMODULE hLibrary);

VOID store_loaded_dll(
    IN PLOADED_PE_INFO peinfo,
    IN HMODULE dll,
    IN PCHAR name);

FARPROC WINAPI my_get_proc_address(
    IN HMODULE hModule,
    IN LPSTR lpProcName);

HMODULE WINAPI my_get_module_handle_w(
  IN LPCWSTR lpModuleName);

#ifdef _WIN64
BOOL insert_inverted_function_table_entry(
    IN PVOID base_address,
    IN SIZE_T size_of_image,
    IN PRUNTIME_FUNCTION func_table,
    IN DWORD size_of_table);

BOOL remove_inverted_function_table_entry(
    IN PRUNTIME_FUNCTION func_table);
#endif

HANDLE get_console_handle(VOID);

VOID set_console_handle(
	IN HANDLE hConsoleHandle);

HANDLE get_std_out_handle(VOID);

VOID set_std_out_handle(
	IN HANDLE hStdOutErr);

HANDLE get_std_err_handle(VOID);

VOID set_std_err_handle(
	IN HANDLE hStdOutErr);

HANDLE get_std_in_handle(VOID);

DWORD get_tid(VOID);

VOID rtl_exit_user_thread(VOID);

BOOL create_thread(
    OUT PHANDLE hThread);

BOOL read_local_pe(
    IN LPCTSTR path,
    OUT PVOID* data,
    OUT int* pelen);
