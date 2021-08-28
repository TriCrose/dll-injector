# DLL Injector
To build: `.\build.ps1` (clang required)
To run: `.\Injector.exe`

The injector starts up a suspended `notepad.exe` and then creates a thread that calls `LoadLibrary` to load the hook. Once loaded, the process is resumed from suspension.

The hook works by locating the import address table and finding the target function (in this case, `CreateFontIndirectW`). It then overwrites that function pointer so that the DLL's own `Hook_CreateFontIndirectW` is called instead.
