#pragma once

BOOL is_pe(
    IN HMODULE hLibrary);

BOOL is_dll(
    IN HMODULE hLibrary);

VOID store_loaded_dll(
    IN PLOADED_PE_INFO peinfo,
    IN HMODULE dll,
    IN PCHAR name);

FARPROC my_get_proc_address(
    IN HMODULE hModule,
    IN LPSTR lpProcName);

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

BOOL create_thread(
    OUT PHANDLE hThread);

BOOL read_local_pe(
    IN LPCTSTR path,
    OUT PVOID* data,
    OUT int* pelen);
