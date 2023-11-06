#pragma once

LPVOID xGetProcAddress(
    IN LPVOID base,
    IN PCHAR api_name,
    IN DWORD ordinal);

LPVOID xGetLibAddress(
    IN PCHAR search,
    IN BOOL load,
    OUT PBOOL loaded);
