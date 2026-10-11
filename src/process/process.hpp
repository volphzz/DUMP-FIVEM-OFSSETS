#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <vector>

namespace process {
    struct ProcessTarget {
        DWORD pid = 0;
        std::string name;
        uintptr_t base_address = 0;
        DWORD module_size = 0;
        int build = 0;
    };

    /**
     * @brief Finds FiveM game process using both window matching and process snapshots.
     * @return Target process metadata, or pid == 0 if not found.
     */
    ProcessTarget find_fivem_process();

    /**
     * @brief Retrieves base address of the main executable module.
     */
    uintptr_t get_base_address(DWORD pid);

    /**
     * @brief Retrieves total size of the main executable module.
     */
    DWORD get_module_size(DWORD pid);

    /**
     * @brief Gets process name.
     */
    std::string get_name(DWORD pid);

    /**
     * @brief Dumps committed executable module memory into a vector buffer.
     */
    bool dump_module_buffer(HANDLE process_handle, uintptr_t base_address, DWORD module_size, std::vector<uint8_t>& buffer);
}
