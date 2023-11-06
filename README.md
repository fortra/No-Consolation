# No-Consolation

This is a Beacon Object File (BOF) that executes unmanaged PEs inline and retrieves their output without allocating a console (i.e. spawning `conhost.exe`).  

![screenshot](resources/demo.png)

## Features
- Supports 64 and 32 bits
- Supports EXEs and DLLs
- Does not create new processes

## Usage
```
Summary: Run an unmanaged EXE/DLL inside Beacon's memory.

Usage: noconsolation [--local] [--timeout 60] [-k] [--method funcname] [-w] [--no-output] [--alloc-console] [--close-handles] [--free-libraries] /path/to/binary.exe arg1 arg2
    --local, -l                           Optional. The binary should be loaded from the target Windows machine
    --timeout NUM_SECONDS, -t NUM_SECONDS Optional. The number of seconds you wish to wait for the PE to complete running. Default 60 seconds. Set to 0 to disable
    -k                                    Optional. Overwrite the PE headers
    --method EXPORT_NAME, -m EXPORT_NAME  Optional. Method or function name to execute in case of DLL. If not provided, DllMain will be executed
    -w                                    Optional. Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)
    --no-output, -no                      Optional. Do not try to obtain the output
    --alloc-console, -ac                  Optional. Allocate a console. This will spawn a new process
    --close-handles, -ch                  Optional. Close Pipe handles once finished. If PowerShell was already ran, this will break the output for PowerShell in the future
    --free-libraries, -fl                 Optional. Free all loaded DLLs
    /path/to/binary.exe                   Required. Full path to the windows EXE/DLL you wish you run inside Beacon
    ARG1 ARG2                             Optional. Parameters for the PE. Must be provided after the path

    Example: noconsolation --local C:\windows\system32\windowspowershell\v1.0\powershell.exe $ExecutionContext.SessionState.LanguageMode
    Example: noconsolation /tmp/mimikatz.exe privilege::debug token::elevate exit
    Example: noconsolation --local C:\windows\system32\cmd.exe /c ipconfig
```

## Credits
- [Octoberfest7](https://twitter.com/octoberfest73) for [Inline-Execute-PE](https://github.com/Octoberfest7/Inline-Execute-PE) which was my inspiration for this project
- [TheWover](https://twitter.com/TheRealWover) for the PE load logic from [donut](https://github.com/TheWover/donut)
- [rad9800](https://twitter.com/rad9800) for his [HWBP engine](https://github.com/rad9800/hwbp4mw)
