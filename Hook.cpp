#include <Windows.h>
#include <Psapi.h>

#include <string>

bool HookModuleFn(const std::string& module, const std::string& function, ULONGLONG hooked_fn) {
    // Get module info for current running process
    auto module_info = MODULEINFO{};
    auto module_handle = GetModuleHandle(nullptr);
    GetModuleInformation(GetCurrentProcess(), module_handle, &module_info, sizeof(MODULEINFO));

    // Find import address table
    auto dll_base_address = static_cast<LPBYTE>(module_info.lpBaseOfDll);
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base_address);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_base_address + dos_header->e_lfanew);
    auto optional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&nt_headers->OptionalHeader);
    auto import_address_table = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        dll_base_address + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    );

    auto found_module = false;
    auto found_fn = false;

    // Find the module we want
    for (auto entry = import_address_table; entry->Characteristics; entry++) {
        auto name = reinterpret_cast<char*>(dll_base_address + entry->Name);
        if (name == module) {       // Found it
            found_module = true;

            auto original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(dll_base_address + entry->OriginalFirstThunk);
            auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(dll_base_address + entry->FirstThunk);

            // Now find the function that we want
            for (auto ot = original_thunk;
                 !(ot->u1.Ordinal & IMAGE_ORDINAL_FLAG) && ot->u1.AddressOfData;
                 ot++, first_thunk++)
            {
                auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dll_base_address + ot->u1.AddressOfData);
                if (import_by_name->Name == function) {   // Found it
                    found_fn = true;

                    // First, gain write access to the function pointer
                    auto old_permissions = DWORD{};
                    VirtualProtect(&first_thunk->u1.Function, sizeof(DWORD), PAGE_READWRITE, &old_permissions);

                    // Change the function to point to our hook instead
                    first_thunk->u1.Function = hooked_fn;

                    // Restore previous permissions
                    VirtualProtect(&first_thunk->u1.Function, sizeof(DWORD), old_permissions, NULL);
                    break;
                }
            }

            break;
        }
    }

    CloseHandle(module_handle);

    if (!found_module) {
        MessageBox(NULL, "Failed to locate module to hook into", "DLL Injection Error", MB_OK | MB_ICONEXCLAMATION);
        return false;
    } else if (!found_fn) {
        MessageBox(NULL, "Failed to locate function import", "DLL Injection Error", MB_OK | MB_ICONEXCLAMATION);
        return false;
    }

    return true;
}

/* Hook the API function that notepad uses to create its font so it always returns Comic Sans */

HFONT Hook_CreateFontIndirectW(LOGFONTW*) {
    return CreateFont(70, 0, 0, 0, 0, TRUE, 0, TRUE, 0, 0, 0, 0, 0, "Comic Sans MS");
}

bool DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason != DLL_PROCESS_ATTACH) { return true; }
    return HookModuleFn("GDI32.dll", "CreateFontIndirectW", reinterpret_cast<ULONGLONG>(Hook_CreateFontIndirectW));
}
