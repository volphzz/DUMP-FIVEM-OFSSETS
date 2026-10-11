#define NOMINMAX
#include "process.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Psapi.lib")

namespace process {
    static std::string to_lower(std::string str) {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return str;
    }

    static int parse_build(const std::string& name) {
        size_t b_pos = name.find("_b");
        if (b_pos != std::string::npos) {
            std::string build_str = name.substr(b_pos + 2);
            try {
                return std::stoi(build_str);
            } catch (...) {}
        }
        return 0;
    }

    uintptr_t get_base_address(DWORD pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                CloseHandle(snap);
                return reinterpret_cast<uintptr_t>(me.modBaseAddr);
            }
            CloseHandle(snap);
        }

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) return 0;

        HMODULE modules[1024];
        DWORD needed = 0;
        if (EnumProcessModules(hProc, modules, sizeof(modules), &needed) && needed >= sizeof(HMODULE)) {
            CloseHandle(hProc);
            return reinterpret_cast<uintptr_t>(modules[0]);
        }

        CloseHandle(hProc);
        return 0;
    }

    DWORD get_module_size(DWORD pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                CloseHandle(snap);
                return me.modBaseSize;
            }
            CloseHandle(snap);
        }

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) return 0;

        HMODULE first_mod = nullptr;
        DWORD needed = 0;
        if (EnumProcessModules(hProc, &first_mod, sizeof(first_mod), &needed)) {
            MODULEINFO modInfo = { 0 };
            if (GetModuleInformation(hProc, first_mod, &modInfo, sizeof(MODULEINFO))) {
                CloseHandle(hProc);
                return modInfo.SizeOfImage;
            }
        }

        CloseHandle(hProc);
        return 0;
    }

    std::string get_name(DWORD pid) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) return {};

        char name_buffer[MAX_PATH] = { 0 };
        if (GetProcessImageFileNameA(hProc, name_buffer, sizeof(name_buffer)) > 0) {
            std::string full_path(name_buffer);
            size_t slash = full_path.find_last_of("\\/");
            CloseHandle(hProc);
            return (slash != std::string::npos) ? full_path.substr(slash + 1) : full_path;
        }

        HMODULE first_mod = nullptr;
        DWORD needed = 0;
        if (EnumProcessModules(hProc, &first_mod, sizeof(first_mod), &needed)) {
            GetModuleBaseNameA(hProc, first_mod, name_buffer, sizeof(name_buffer));
        }

        CloseHandle(hProc);
        return std::string(name_buffer);
    }

    ProcessTarget find_fivem_process() {
        ProcessTarget target;

        // Strategy 1: Check active window
        HWND window = FindWindowA("grcWindow", nullptr);
        if (window) {
            DWORD pid = 0;
            GetWindowThreadProcessId(window, &pid);
            if (pid) {
                target.pid = pid;
                target.name = get_name(pid);
                target.build = parse_build(target.name);
                target.base_address = get_base_address(pid);
                target.module_size = get_module_size(pid);
                if (target.base_address && target.module_size && to_lower(target.name).find("gtaprocess") != std::string::npos) {
                    return target;
                }
            }
        }

        // Strategy 2: Toolhelp snapshot search for known FiveM game processes
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    char narrow_name[MAX_PATH] = { 0 };
                    WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow_name, sizeof(narrow_name), nullptr, nullptr);
                    std::string exe_name(narrow_name);
                    std::string lower = to_lower(exe_name);

                    if (lower.find("fivem_b") != std::string::npos ||
                        lower.find("gtaprocess") != std::string::npos ||
                        lower.find("gameprocess") != std::string::npos ||
                        lower == "gta5.exe") {
                        
                        target.pid = pe.th32ProcessID;
                        target.name = exe_name;
                        target.build = parse_build(exe_name);
                        target.base_address = get_base_address(target.pid);
                        target.module_size = get_module_size(target.pid);

                        if (target.base_address && target.module_size && to_lower(target.name).find("gtaprocess") != std::string::npos) {
                            CloseHandle(snap);
                            return target;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        return target;
    }

    bool dump_module_buffer(HANDLE process_handle, uintptr_t base_address, DWORD module_size, std::vector<uint8_t>& buffer) {
        if (!process_handle || !base_address || !module_size) return false;
        
        buffer.assign(module_size, 0);
        const uintptr_t end = base_address + module_size;
        size_t total_read = 0;
        for (uintptr_t current = base_address; current < end;) {
            MEMORY_BASIC_INFORMATION info{};
            if (!VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(current), &info, sizeof(info))) break;
            const uintptr_t region_end = std::min(end, reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize);
            if (region_end <= current) break;
            if (info.State == MEM_COMMIT && !(info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                for (uintptr_t page = current; page < region_end;) {
                    SIZE_T n = std::min<SIZE_T>(4096 - (page % 4096), region_end - page), got = 0;
                    ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(page), buffer.data() + (page - base_address), n, &got);
                    total_read += got;
                    page += n;
                }
            }
            current = region_end;
        }
        return total_read > 0;
    }
}
