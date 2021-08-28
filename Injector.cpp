#include <Windows.h>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <Shlwapi.h>

#include <iostream>
#include <string>
#include <array>

const std::string kProcessToInject {"C:\\Windows\\System32\\notepad.exe"};

std::string GetHookDllPath() {
    auto path = std::array<char, MAX_PATH>();
    GetModuleFileName(NULL, path.data(), MAX_PATH);
    PathRemoveFileSpec(path.data());

    auto dll_path = std::array<char, MAX_PATH>();
    PathCombine(dll_path.data(), path.data(), "Hook.dll");

    return std::string{dll_path.data()};
}

int main() {
    auto startup_info = STARTUPINFO{};
    auto proc_info = PROCESS_INFORMATION{};
    auto hook_path = GetHookDllPath();

    if (!PathFileExists(hook_path.c_str())) {
        std::cerr << "Cannot find DLL hook '" << hook_path << "'";
        return 1;
    }

    // Create process in suspended state
    if (!CreateProcess(kProcessToInject.c_str(), NULL, NULL, NULL,
                       FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &proc_info)) {
        std::cerr << "Failed to create process for '" << kProcessToInject << "'";
        return 1;
    }

    // Allocate memory in the target process to store hook DLL path
    auto remote_address = VirtualAllocEx(proc_info.hProcess, NULL,
                                         hook_path.length() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remote_address) {
        std::cerr << "Failed to allocate memory in the target process";
        CloseHandle(proc_info.hProcess);
        return 1;
    }

    // Write the DLL path to the newly-allocated memory
    if (!WriteProcessMemory(proc_info.hProcess, remote_address,
                            hook_path.c_str(), hook_path.length() + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process memory";
        VirtualFreeEx(proc_info.hProcess, remote_address, 0, MEM_RELEASE);
        CloseHandle(proc_info.hProcess);
        return 1;
    }

    // Create remote thread to load the hook DLL
    auto load_library_fn = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    auto thread = CreateRemoteThread(proc_info.hProcess, NULL, NULL,
                                     reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library_fn), remote_address, NULL, NULL);
    if (!thread) {
        std::cerr << "Failed to create remote thread in target process";
        VirtualFreeEx(proc_info.hProcess, remote_address, 0, MEM_RELEASE);
        CloseHandle(proc_info.hProcess);
        return 1;
    }

    // Wait for the thread to load the DLL
    WaitForSingleObject(thread, 5000);

    // Resume the process from suspension
    std::cout << "DLL injected.";
    ResumeThread(proc_info.hThread);

    return 0;
}
