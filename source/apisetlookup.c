/**
 * API Set Lookup
 * Copyright (c) 2018-2019 Aidan Khoury. All rights reserved.
 *
 * @file apiset.c
 * @authors Aidan Khoury (ajkhoury)
 * @date 11/22/2018
 */

#include "apisetlookup.h"

//
// ApiSet DLL prefixes.
//

#define API_SET_DLL_EXTENSTION  (ULONGLONG)0x004C004C0044002E /* L".DLL" */

//
// Useful macros for ApiSet api.
//

#define API_SET_CHAR_TO_LOWER(c) \
    (((WCHAR)((c) - L'A') <= (L'a' - L'A' - 1)) ? ((c) + 0x20) : (c))


//
// API set schema version 6.
//

#define GET_API_SET_NAMESPACE_ENTRY_V6(ApiSetNamespace, Index) \
    ((PAPI_SET_NAMESPACE_ENTRY_V6)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_V6)(ApiSetNamespace))->EntryOffset + \
                                    ((Index) * sizeof(API_SET_NAMESPACE_ENTRY_V6))))

#define GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespace, Entry, Index) \
    ((PAPI_SET_VALUE_ENTRY_V6)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ENTRY_V6)(Entry))->ValueOffset + \
                                    ((Index) * sizeof(API_SET_VALUE_ENTRY_V6))))

#define GET_API_SET_NAMESPACE_ENTRY_NAME_V6(ApiSetNamespace, Entry) \
    ((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_NAMESPACE_ENTRY_V6)(Entry))->NameOffset))

#define GET_API_SET_NAMESPACE_ENTRY_VALUE_V6(ApiSetNamespace, Entry) \
    ((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_NAMESPACE_ENTRY_V6)(Entry))->ValueOffset))

#define GET_API_SET_VALUE_ENTRY_NAME_V6(ApiSetNamespace, Entry) \
    ((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_VALUE_ENTRY_V6)(Entry))->NameOffset))

#define GET_API_SET_VALUE_ENTRY_VALUE_V6(ApiSetNamespace, Entry) \
    ((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_VALUE_ENTRY_V6)(Entry))->ValueOffset))

#define GET_API_SET_HASH_ENTRY_V6(ApiSetNamespace, Middle) \
    ((PAPI_SET_HASH_ENTRY_V6)((ULONG_PTR)(ApiSetNamespace) + \
                            ((PAPI_SET_NAMESPACE_V6)(ApiSetNamespace))->HashOffset + \
                                ((Middle) * sizeof(API_SET_HASH_ENTRY_V6))))

PAPI_SET_NAMESPACE_ENTRY_V6
ApiSetpSearchForApiSetV6(
    IN PAPI_SET_NAMESPACE_V6 ApiSetNamespace,
    IN PWCHAR ApiSetNameToResolve,
    IN USHORT ApiSetNameToResolveLength
)
{
    PWCHAR                 pwc             = NULL;
    USHORT                 Count           = 0;
    ULONG                  HashKey         = 0;
    LONG                   Low             = 0;
    LONG                   Middle          = 0;
    LONG                   High            = 0;
    PAPI_SET_HASH_ENTRY_V6 HashEntry       = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V6 FoundEntry = NULL;

    if (!ApiSetNameToResolveLength) {
        return NULL;
    }

    //
    // Calculate hash key for this ApiSet name.
    //
    HashKey = 0;
    pwc = ApiSetNameToResolve;
    Count = ApiSetNameToResolveLength;
    do {
        HashKey = HashKey * ApiSetNamespace->HashFactor + (USHORT)API_SET_CHAR_TO_LOWER(*pwc);
        ++pwc;
        --Count;
    } while (Count);

    //
    // Lookup the matching hash in the ApiSet namespace using a binary search.
    //
    FoundEntry = NULL;
    Low = 0;
    Middle = 0;
    High = (LONG)ApiSetNamespace->Count - 1;

    while (High >= Low) {
        Middle = (Low + High) >> 1;

        HashEntry = GET_API_SET_HASH_ENTRY_V6(ApiSetNamespace, Middle);

        if (HashKey < HashEntry->Hash) {
            High = Middle - 1;
        } else if (HashKey > HashEntry->Hash) {
            Low = Middle + 1;
        } else {
            //
            // Get the namespace entry from the hash entry index.
            //
            FoundEntry = GET_API_SET_NAMESPACE_ENTRY_V6(ApiSetNamespace, HashEntry->Index);
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching hash entry was not found.
    // Otherwise, get the found namespace entry.
    //
    if (High < Low) {
        return NULL;
    }

    //
    // Final check on apiset library name in order to make sure we didn't collide with
    // another hash bucket.
    //
    if (RtlCompareUnicodeStrings(ApiSetNameToResolve,
                                 ApiSetNameToResolveLength,
                                 GET_API_SET_NAMESPACE_ENTRY_NAME_V6(ApiSetNamespace, FoundEntry),
                                 FoundEntry->HashedLength / sizeof(WCHAR),
                                 TRUE) == 0) {
        return FoundEntry;
    }

    return NULL;
}

PAPI_SET_VALUE_ENTRY_V6
ApiSetpSearchForApiSetHostV6(
    IN PAPI_SET_NAMESPACE_ENTRY_V6 Entry,
    IN WCHAR *ApiSetNameToResolve,
    IN USHORT ApiSetNameToResolveLength,
    IN PAPI_SET_NAMESPACE_V6 ApiSetNamespace)
{
    LONG                    Low             = 0;
    LONG                    Middle          = 0;
    LONG                    High            = 0;
    LONG                    Result          = 0;
    PAPI_SET_VALUE_ENTRY_V6 FoundEntry      = NULL;
    PAPI_SET_VALUE_ENTRY_V6 ApiSetHostEntry = NULL;

    //
    // If there is no alias, don't bother checking each one.
    //
    FoundEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespace, Entry, 0);

    High = (LONG)(Entry->ValueCount - 1);
    if (!High) {
        return FoundEntry;
    }

    Low = 1; // skip the first entry.

    while (Low <= High) {
        Middle = (Low + High) >> 1;

        ApiSetHostEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespace, Entry, Middle);

        //
        // Compare API names.
        //
        Result = RtlCompareUnicodeStrings(ApiSetNameToResolve,
                                          ApiSetNameToResolveLength,
                                          GET_API_SET_VALUE_ENTRY_NAME_V6(ApiSetNamespace, ApiSetHostEntry),
                                          ApiSetHostEntry->NameLength / sizeof(WCHAR),
                                          TRUE);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            FoundEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespace, Entry, Middle);
            break;
        }
    }

    return FoundEntry;
}

BOOL ApiSetResolveToHostV6(
    IN PAPI_SET_NAMESPACE ApiSetNamespace,
    IN PUNICODE_STRING ApiSetNameToResolve,
    IN PUNICODE_STRING ParentName,
    OUT PUNICODE_STRING Output)
{
    BOOL                        IsResolved             = FALSE;
    PWCHAR                      ApiSetNameBuffer       = 0;
    PWCHAR                      pwc                    = 0;
    ULONG                       ApiSetNameBufferLength = 0;
    USHORT                      ApiSetNameNoExtLength  = 0;
    PAPI_SET_NAMESPACE_ENTRY_V6 ResolvedNamespaceEntry = NULL;
    PAPI_SET_VALUE_ENTRY_V6     HostLibraryEntry       = NULL;

    RtlInitEmptyUnicodeString(Output, NULL, 0);

    ApiSetNameBuffer = ApiSetNameToResolve->Buffer;

    //
    // Compute word count of apiset library name without the dll suffix and anything
    // beyond the last hyphen. Example: 
    //     api-ms-win-core-apiquery-l1-1-0.dll -> wordlen(api-ms-win-core-apiquery-l1-1)
    //
    ApiSetNameBufferLength = (ULONG)ApiSetNameToResolve->Length;
    pwc = RVA2VA(PWCHAR, ApiSetNameBuffer, ApiSetNameBufferLength);
    do {
        if (ApiSetNameBufferLength <= 1)
            break;
        ApiSetNameBufferLength -= sizeof(WCHAR);
        --pwc;
    } while (*pwc != L'-');

    ApiSetNameNoExtLength = (USHORT)(ApiSetNameBufferLength / sizeof(WCHAR));
    if (!ApiSetNameNoExtLength) {
        goto Exit;
    }

    //
    // Hash table lookup.
    //
    ResolvedNamespaceEntry = ApiSetpSearchForApiSetV6(
        (PAPI_SET_NAMESPACE_V6)ApiSetNamespace,
        ApiSetNameBuffer,
        ApiSetNameNoExtLength);
    if (!ResolvedNamespaceEntry) {
        goto Exit;
    }

    //
    // Look for aliases in hosts libraries if necessary.
    //
    if (ResolvedNamespaceEntry->ValueCount > 1 && ParentName) {

        HostLibraryEntry = ApiSetpSearchForApiSetHostV6(
            ResolvedNamespaceEntry,
            ParentName->Buffer,
            ParentName->Length / sizeof(WCHAR),
            (PAPI_SET_NAMESPACE_V6)ApiSetNamespace);

    } else if (ResolvedNamespaceEntry->ValueCount > 0) {

        HostLibraryEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespace,
                                                                ResolvedNamespaceEntry,
                                                                0);
    } else {
        goto Exit;
    }

    //
    // Output resolved host library.
    //
    Output->Length = (USHORT)HostLibraryEntry->ValueLength;
    Output->MaximumLength = Output->Length;
    Output->Buffer = GET_API_SET_VALUE_ENTRY_VALUE_V6(ApiSetNamespace, HostLibraryEntry);

    IsResolved = TRUE;

Exit:
    return IsResolved;
}



//
// API set schema version 4.
//

#define GET_API_SET_NAMESPACE_ENTRY_V4(ApiSetNamespace, Index) \
    ((PAPI_SET_NAMESPACE_ENTRY_V4)(((PAPI_SET_NAMESPACE_ARRAY_V4)(ApiSetNamespace))->Array + \
                                        Index))

#define GET_API_SET_NAMESPACE_ENTRY_NAME_V4(ApiSetNamespace, NamespaceEntry) \
    ((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + \
                ((PAPI_SET_NAMESPACE_ENTRY_V4)(NamespaceEntry))->NameOffset))

#define GET_API_SET_NAMESPACE_ENTRY_DATA_V4(ApiSetNamespace, NamespaceEntry) \
    ((PAPI_SET_VALUE_ARRAY_V4)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ENTRY_V4)(NamespaceEntry))->DataOffset))

#define GET_API_SET_VALUE_ENTRY_V4(ApiSetNamespace, ResolvedValueArray, Index) \
    ((PAPI_SET_VALUE_ENTRY_V4)(((PAPI_SET_VALUE_ARRAY_V4)(ResolvedValueArray))->Array + \
                                        Index))

#define GET_API_SET_VALUE_ENTRY_NAME_V4(ApiSetNamespace, ApiSetValueEntry) \
    ((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
                ((PAPI_SET_VALUE_ENTRY_V4)(ApiSetValueEntry))->NameOffset))

#define GET_API_SET_VALUE_ENTRY_VALUE_V4(ApiSetNamespace, ApiSetValueEntry) \
    ((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
                ((PAPI_SET_VALUE_ENTRY_V4)(ApiSetValueEntry))->ValueOffset))

PAPI_SET_NAMESPACE_ENTRY_V4
ApiSetpSearchForApiSetV4(
    IN PAPI_SET_NAMESPACE ApiSetNamespace,
    IN PWCHAR ApiSetNameToResolve,
    IN USHORT ApiSetNameToResolveLength
)
{
    LONG                        Low                  = 0;
    LONG                        Middle               = 0;
    LONG                        High                 = 0;
    LONG                        Result               = 0;
    PAPI_SET_NAMESPACE_ARRAY_V4 ApiSetNamespaceArray = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V4 ApiSetNamespaceEntry = NULL;

    ApiSetNamespaceArray = (PAPI_SET_NAMESPACE_ARRAY_V4)ApiSetNamespace;

    Low = 0;
    High = (LONG)(ApiSetNamespaceArray->Count - 1);

    while (High >= Low) {
        Middle = (High + Low) >> 1;

        ApiSetNamespaceEntry = GET_API_SET_NAMESPACE_ENTRY_V4(ApiSetNamespace, Middle);

        Result = RtlCompareUnicodeStrings(
            ApiSetNameToResolve,
            ApiSetNameToResolveLength,
            GET_API_SET_NAMESPACE_ENTRY_NAME_V4(ApiSetNamespace, ApiSetNamespaceEntry),
            ApiSetNamespaceEntry->NameLength,
            TRUE);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            return ApiSetNamespaceEntry;
        }
    }

    return NULL;
}

PAPI_SET_VALUE_ENTRY_V4
ApiSetpSearchForApiSetHostV4(
    IN PAPI_SET_VALUE_ARRAY_V4 ApiSetValueArray,
    IN WCHAR *ApiSetNameToResolve,
    IN USHORT ApiSetNameToResolveLength,
    IN PAPI_SET_NAMESPACE_ARRAY_V4 ApiSetNamespace)
{
    LONG                    Low             = 0;
    LONG                    Middle          = 0;
    LONG                    High            = 0;
    LONG                    Result          = 0;
    PAPI_SET_VALUE_ENTRY_V4 ApiSetHostEntry = NULL;

    Low = 1; // skip first entry.
    High = (LONG)(ApiSetValueArray->Count - 1);

    while (High >= Low) {
        Middle = (High + Low) >> 1;

        ApiSetHostEntry = GET_API_SET_VALUE_ENTRY_V4(ApiSetNamespace, ApiSetValueArray, Middle);

        Result = RtlCompareUnicodeStrings(
            ApiSetNameToResolve,
            ApiSetNameToResolveLength,
            GET_API_SET_VALUE_ENTRY_NAME_V4(ApiSetNamespace, ApiSetHostEntry),
            ApiSetHostEntry->NameLength,
            TRUE);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            return ApiSetHostEntry;
        }
    }

    return NULL;
}

BOOL ApiSetResolveToHostV4(
    IN PAPI_SET_NAMESPACE ApiSetNamespace,
    IN PUNICODE_STRING ApiSetNameToResolve,
    IN PUNICODE_STRING ParentName,
    OUT PUNICODE_STRING Output)
{
    BOOL                        IsResolved             = FALSE;
    PAPI_SET_NAMESPACE_ENTRY_V4 ResolvedNamespaceEntry = NULL;
    PAPI_SET_VALUE_ARRAY_V4     ResolvedValueArray     = NULL;
    PAPI_SET_VALUE_ENTRY_V4     HostLibraryEntry       = NULL;
    UNICODE_STRING              ApiSetNameNoExtString  = { 0 };

    RtlInitEmptyUnicodeString(Output, NULL, 0);

    //
    // Skip the prefix.
    //
    ApiSetNameNoExtString.Length = ApiSetNameToResolve->Length - 8;
    ApiSetNameNoExtString.MaximumLength = ApiSetNameNoExtString.Length;
    ApiSetNameNoExtString.Buffer = RVA2VA(PWCHAR, ApiSetNameToResolve->Buffer, 8);

    //
    // Cut off the '.DLL' extension.
    //
    if (ApiSetNameNoExtString.Length >= sizeof(API_SET_DLL_EXTENSTION) &&
        ApiSetNameNoExtString.Buffer[(ApiSetNameNoExtString.Length -
                                      sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] == L'.') {
        ApiSetNameNoExtString.Length -= sizeof(API_SET_DLL_EXTENSTION);
    }

    ResolvedNamespaceEntry = ApiSetpSearchForApiSetV4(
        ApiSetNamespace,
        ApiSetNameNoExtString.Buffer,
        ApiSetNameNoExtString.Length / sizeof(WCHAR));
    if (!ResolvedNamespaceEntry) {
        goto Exit;
    }

    //
    // Get the namspace value array.
    //
    ResolvedValueArray = GET_API_SET_NAMESPACE_ENTRY_DATA_V4(ApiSetNamespace,
                                                             ResolvedNamespaceEntry);

    //
    // Look for aliases in hosts libraries if necessary.
    //
    if (ResolvedValueArray->Count > 1 && ParentName) {

        HostLibraryEntry = ApiSetpSearchForApiSetHostV4(
            ResolvedValueArray,
            ParentName->Buffer,
            ParentName->Length / sizeof(WCHAR),
            (PAPI_SET_NAMESPACE_ARRAY_V4)ApiSetNamespace);

    } else if (ResolvedValueArray->Count > 0) {
        HostLibraryEntry = GET_API_SET_VALUE_ENTRY_V4(ApiSetNamespace, ResolvedValueArray, 0);
    } else {
        goto Exit;
    }

    Output->Length = (USHORT)HostLibraryEntry->ValueLength;
    Output->MaximumLength = Output->Length;
    Output->Buffer = GET_API_SET_VALUE_ENTRY_VALUE_V4(ApiSetNamespace, HostLibraryEntry);

    IsResolved = TRUE;

Exit:
    return IsResolved;
}



//
// API Set Schema Version 3
//

#define GET_API_SET_NAMESPACE_ENTRY_V3(ApiSetNamespace, Index) \
    ((PAPI_SET_NAMESPACE_ENTRY_V3)(((PAPI_SET_NAMESPACE_ARRAY_V3)(ApiSetNamespace))->Array + \
                                        Index))

#define GET_API_SET_NAMESPACE_ENTRY_NAME_V3(ApiSetNamespace, NamespaceEntry) \
    ((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + \
                ((PAPI_SET_NAMESPACE_ENTRY_V3)(NamespaceEntry))->NameOffset))

#define GET_API_SET_NAMESPACE_ENTRY_DATA_V3(ApiSetNamespace, NamespaceEntry) \
    ((PAPI_SET_VALUE_ARRAY_V3)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ENTRY_V3)(NamespaceEntry))->DataOffset))

#define GET_API_SET_VALUE_ENTRY_V3(ApiSetNamespace, ResolvedValueArray, Index) \
    ((PAPI_SET_VALUE_ENTRY_V3)(((PAPI_SET_VALUE_ARRAY_V3)(ResolvedValueArray))->Array + \
                                        Index))

#define GET_API_SET_VALUE_ENTRY_NAME_V3(ApiSetNamespace, ApiSetValueEntry) \
    ((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
                ((PAPI_SET_VALUE_ENTRY_V3)(ApiSetValueEntry))->NameOffset))

#define GET_API_SET_VALUE_ENTRY_VALUE_V3(ApiSetNamespace, ApiSetValueEntry) \
    ((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
                ((PAPI_SET_VALUE_ENTRY_V3)(ApiSetValueEntry))->ValueOffset))

PAPI_SET_VALUE_ENTRY_V3
ApiSetpSearchForApiSetHostV3(
    IN PAPI_SET_VALUE_ARRAY_V3 ApiSetValueArray,
    IN WCHAR *ApiSetNameToResolve,
    IN USHORT ApiSetNameToResolveLength,
    IN PAPI_SET_NAMESPACE_ARRAY_V3 ApiSetNamespace)
{
    LONG Low                                 = 0;
    LONG Middle                              = 0;
    LONG High                                = 0;
    LONG Result                              = 0;
    PAPI_SET_VALUE_ENTRY_V3 ApiSetValueEntry = NULL;

    Low = 1; // skip first entry.
    High = ApiSetValueArray->Count - 1;

    while (High >= Low) {
        Middle = (High + Low) >> 1;

        ApiSetValueEntry = GET_API_SET_VALUE_ENTRY_V3(ApiSetNamespace, ApiSetValueArray, Middle);

        Result = RtlCompareUnicodeStrings(
            ApiSetNameToResolve,
            ApiSetNameToResolveLength,
            GET_API_SET_VALUE_ENTRY_NAME_V3(ApiSetNamespace, ApiSetValueEntry),
            ApiSetValueEntry->NameLength,
            TRUE);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            return ApiSetValueEntry;
        }
    }

    return NULL;
}

BOOL ApiSetResolveToHostV3(
    IN PAPI_SET_NAMESPACE ApiSetNamespace,
    IN PUNICODE_STRING ApiSetNameToResolve,
    IN PUNICODE_STRING ParentName,
    OUT PUNICODE_STRING Output)
{
    BOOL                        IsResolved             = FALSE;
    LONG                        Low                    = 0;
    LONG                        Middle                 = 0;
    LONG                        High                   = 0;
    LONG                        Result                 = 0;
    PAPI_SET_NAMESPACE_ARRAY_V3 ApiSetNamespaceArray   = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V3 ResolvedNamespaceEntry = NULL;
    PAPI_SET_VALUE_ARRAY_V3     ResolvedValueArray     = NULL;
    PAPI_SET_VALUE_ENTRY_V3     HostLibraryEntry       = NULL;
    UNICODE_STRING              ApiSetNameNoExtString  = { 0 };

    RtlInitEmptyUnicodeString(Output, NULL, 0);

    //
    // Skip the prefix.
    //
    ApiSetNameNoExtString.Length = ApiSetNameToResolve->Length - 8;
    ApiSetNameNoExtString.MaximumLength = ApiSetNameNoExtString.Length;
    ApiSetNameNoExtString.Buffer = RVA2VA(PWCHAR, ApiSetNameToResolve->Buffer, 8);

    //
    // Cut off the '.DLL' extension.
    //
    if (ApiSetNameNoExtString.Length >= sizeof(API_SET_DLL_EXTENSTION) &&
        ApiSetNameNoExtString.Buffer[(ApiSetNameNoExtString.Length -
                                      sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] == L'.') {
        ApiSetNameNoExtString.Length -= sizeof(API_SET_DLL_EXTENSTION);
    }

    ApiSetNamespaceArray = (PAPI_SET_NAMESPACE_ARRAY_V3)ApiSetNamespace;
    ResolvedNamespaceEntry = NULL;

    Low = 0;
    High = (LONG)(ApiSetNamespaceArray->Count - 1);

    while (High >= Low) {
        Middle = (Low + High) >> 1;

        ResolvedNamespaceEntry = GET_API_SET_NAMESPACE_ENTRY_V3(ApiSetNamespace, Middle);

        Result = RtlCompareUnicodeStrings(
            ApiSetNameNoExtString.Buffer,
            ApiSetNameNoExtString.Length / sizeof(WCHAR),
            GET_API_SET_NAMESPACE_ENTRY_NAME_V3(ApiSetNamespace, ResolvedNamespaceEntry),
            ResolvedNamespaceEntry->NameLength / sizeof(WCHAR),
            TRUE);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching namespace
    // entry was not found.
    //
    if (High < Low) {
        goto Exit;
    }

    //
    // Get the namspace value array.
    //
    ResolvedValueArray = GET_API_SET_NAMESPACE_ENTRY_DATA_V3(ApiSetNamespace, ResolvedNamespaceEntry);

    //
    // Look for aliases in hosts libraries if necessary.
    //
    if (ResolvedValueArray->Count > 1 && ParentName) {

        HostLibraryEntry = ApiSetpSearchForApiSetHostV3(
            ResolvedValueArray,
            ParentName->Buffer,
            ParentName->Length / sizeof(WCHAR),
            (PAPI_SET_NAMESPACE_ARRAY_V3)ApiSetNamespace);
    } else {
        HostLibraryEntry = NULL;
    }

    //
    // Default to the first value entry.
    //
    if (!HostLibraryEntry) {
        HostLibraryEntry = GET_API_SET_VALUE_ENTRY_V3(ApiSetNamespace, ResolvedValueArray, 0);
    }

    //
    // Output resolved host library.
    //
    Output->Length = (USHORT)HostLibraryEntry->ValueLength;
    Output->MaximumLength = Output->Length;
    Output->Buffer = GET_API_SET_VALUE_ENTRY_VALUE_V3(ApiSetNamespace, HostLibraryEntry);

    IsResolved = TRUE;

Exit:
    return IsResolved;
}



//
// API Set Schema Version 2
//

#define GET_API_SET_NAMESPACE_ENTRY_V2(ApiSetNamespace, Index) \
    ((PAPI_SET_NAMESPACE_ENTRY_V2)((ULONG_PTR)(ApiSetNamespace) + \
                                    ((PAPI_SET_NAMESPACE_ARRAY_V2)(ApiSetNamespace))->Array + \
                                        Index))

PAPI_SET_VALUE_ENTRY_V2
ApiSetpSearchForApiSetHostV2(
    IN PAPI_SET_VALUE_ARRAY_V2 ApiSetValueArray,
    IN PUNICODE_STRING ApiToResolve,
    IN PAPI_SET_NAMESPACE ApiSetNamespace)
{
    LONG                    Low              = 0;
    LONG                    Middle           = 0;
    LONG                    High             = 0;
    LONG                    Result           = 0;
    UNICODE_STRING          ApiSetHostString = { 0 };
    PAPI_SET_VALUE_ENTRY_V2 ApiSetValueEntry = NULL;

    Low = 1; // skip first entry.
    High = ApiSetValueArray->Count - 1;

    while (High >= Low) {
        Middle = (High + Low) >> 1;

        ApiSetValueEntry = &ApiSetValueArray->Array[Middle];
        ApiSetHostString.Length = (USHORT)ApiSetValueEntry->NameLength;
        ApiSetHostString.MaximumLength = ApiSetHostString.Length;
        ApiSetHostString.Buffer = RVA2VA(PWCHAR, ApiSetNamespace, ApiSetValueEntry->NameOffset);

        Result = RtlCompareUnicodeString(ApiToResolve, &ApiSetHostString, TRUE);

        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            return ApiSetValueEntry;
        }
    }

    return NULL;
}

BOOL ApiSetResolveToHostV2(
    IN PAPI_SET_NAMESPACE ApiSetNamespace,
    IN PUNICODE_STRING ApiSetNameToResolve,
    IN PUNICODE_STRING ParentName,
    OUT PUNICODE_STRING Output)
{
    BOOL                        IsResolved            = FALSE;
    LONG                        Low                   = 0;
    LONG                        Middle                = 0;
    LONG                        High                  = 0;
    LONG                        Result                = 0;
    PAPI_SET_NAMESPACE_ARRAY_V2 ApiSetNamespaceArray  = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V2 ApiSetNamespaceEntry  = NULL;
    PAPI_SET_VALUE_ARRAY_V2     ApiSetValueArray      = NULL;
    PAPI_SET_VALUE_ENTRY_V2     HostLibraryEntry      = NULL;
    UNICODE_STRING              ApiSetNamespaceString = { 0 };
    UNICODE_STRING              ApiSetNameNoExtString = { 0 };

    RtlInitEmptyUnicodeString(Output, NULL, 0);

    //
    // Skip the prefix.
    //
    ApiSetNameNoExtString.Length = ApiSetNameToResolve->Length - 8;
    ApiSetNameNoExtString.MaximumLength = ApiSetNameNoExtString.Length;
    ApiSetNameNoExtString.Buffer = RVA2VA(PWCHAR, ApiSetNameToResolve->Buffer, 8);

    //
    // Cut off the '.DLL' extension.
    //
    if (ApiSetNameNoExtString.Length >= sizeof(API_SET_DLL_EXTENSTION) &&
        ApiSetNameNoExtString.Buffer[(ApiSetNameNoExtString.Length -
                                      sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] == L'.') {
        ApiSetNameNoExtString.Length -= sizeof(API_SET_DLL_EXTENSTION);
    }

    ApiSetNamespaceArray = (PAPI_SET_NAMESPACE_ARRAY_V2)ApiSetNamespace;
    ApiSetNamespaceEntry = NULL;

    Low = 0;
    High = (LONG)(ApiSetNamespaceArray->Count - 1);

    while (High >= Low) {
        Middle = (Low + High) >> 1;

        ApiSetNamespaceEntry = GET_API_SET_NAMESPACE_ENTRY_V2(ApiSetNamespace, Middle);
        ApiSetNamespaceString.Length = (USHORT)ApiSetNamespaceEntry->NameLength;
        ApiSetNamespaceString.MaximumLength = ApiSetNamespaceString.Length;
        ApiSetNamespaceString.Buffer = RVA2VA(PWCHAR, ApiSetNamespace, ApiSetNamespaceEntry->NameOffset);

        Result = RtlCompareUnicodeString(&ApiSetNameNoExtString, &ApiSetNamespaceString, TRUE);

        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching namespace
    // entry was not found.
    //
    if (High < Low) {
        goto Exit;
    }

    //
    // Get the namspace value array.
    //
    ApiSetValueArray = RVA2VA(PAPI_SET_VALUE_ARRAY_V2, ApiSetNamespace, ApiSetNamespaceEntry->DataOffset);

    //
    // Look for aliases in hosts libraries if necessary.
    //
    if (ApiSetValueArray->Count > 1 && ParentName) {

        HostLibraryEntry = ApiSetpSearchForApiSetHostV2(
            ApiSetValueArray,
            ParentName,
            ApiSetNamespace);
    } else {
        HostLibraryEntry = NULL;
    }

    //
    // Default to the first value entry.
    //
    if (!HostLibraryEntry) {
        HostLibraryEntry = ApiSetValueArray->Array;
    }

    //
    // Output resolved host library.
    //
    Output->Length = (USHORT)HostLibraryEntry->ValueLength;
    Output->MaximumLength = Output->Length;
    Output->Buffer = RVA2VA(PWCHAR, ApiSetNamespace, HostLibraryEntry->ValueOffset);

    IsResolved = TRUE;

Exit:
    return IsResolved;
}

BOOL ApiSetpResolve(
    IN PUNICODE_STRING Name,
    IN PUNICODE_STRING BaseName,
    OUT PUNICODE_STRING ResolvedName)
{
    PPEB2              peb       = NULL;
    BOOL               Resolved  = FALSE;
    PAPI_SET_NAMESPACE ApiSetMap = NULL;

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ApiSetMap = peb->ApiSetMap;

    switch (ApiSetMap->Version) {

        //
        // API set schema version 2
        //
    case API_SET_SCHEMA_VERSION_V2:
        Resolved = ApiSetResolveToHostV2(ApiSetMap, Name, BaseName, ResolvedName);
        break;

        //
        // API set schema version 3
        //
    case API_SET_SCHEMA_VERSION_V3:
        Resolved = ApiSetResolveToHostV3(ApiSetMap, Name, BaseName, ResolvedName);
        break;

        //
        // API set schema version 4
        //
    case API_SET_SCHEMA_VERSION_V4:
        Resolved = ApiSetResolveToHostV4(ApiSetMap, Name, BaseName, ResolvedName);
        break;

        //
        // API set schema version 6
        //
    case API_SET_SCHEMA_VERSION_V6:
        Resolved = ApiSetResolveToHostV6(ApiSetMap, Name, BaseName, ResolvedName);
        break;

    default:
        DPRINT_ERR("API set version not supported: %d", ApiSetMap->Version);
        return FALSE;
    }

    if (!Resolved)
    {
        DPRINT_ERR("Failed to resolve API Set: %ls", Name->Buffer);
    }

    return Resolved;
}

BOOL is_api_set(
    IN PCHAR dll_name)
{
    if (!strncmp(dll_name, "api-", 4) || !strncmp(dll_name, "ext-", 4))
        return TRUE;
    return FALSE;
}

PCHAR api_set_resolve(
    IN PCHAR dll_name)
{
    BOOL           success        = FALSE;
    UNICODE_STRING api_to_resolve = { 0 };
    UNICODE_STRING uresolved      = { 0 };
    PWCHAR         dll_wname      = NULL;
    PCHAR          resolved       = NULL;

    if (!is_api_set(dll_name))
    {
        resolved = intAlloc(sizeof(CHAR) * MAX_PATH);
        StringCopyA(resolved, dll_name);
        return resolved;
    }

    dll_wname = intAlloc(sizeof(WCHAR) * MAX_PATH);
    CharStringToWCharString(dll_wname, dll_name, MAX_PATH);
    myRtlInitUnicodeString(&api_to_resolve, dll_wname);

    success = ApiSetpResolve(
        &api_to_resolve,
        NULL,
        &uresolved);

    intFree(dll_wname);

    if (!success)
        return NULL;

    resolved = intAlloc(sizeof(CHAR) * MAX_PATH);
    WCharStringToCharString(resolved, uresolved.Buffer, uresolved.MaximumLength / 2);
    //DPRINT("api set resolved %s -> %s", dll_name, resolved);

    return resolved;
}
