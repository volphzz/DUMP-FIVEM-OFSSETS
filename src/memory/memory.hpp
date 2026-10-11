#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace memory {
    struct PatternElement {
        bool is_wildcard;
        uint8_t value;
    };

    struct CompiledPattern {
        std::vector<PatternElement> elements;
        size_t first_non_wildcard_offset = 0;
        uint8_t first_non_wildcard_value = 0;
        bool has_non_wildcard = false;
        bool unique_only = false;
        std::vector<std::pair<size_t, size_t>> code_ranges;
    };

    CompiledPattern compile_pattern(const std::string& pattern);

    /**
     * @brief High-performance byte pattern scanner over memory buffer.
     * @param buffer Read buffer of the target module.
     * @param base_address Module base virtual address in the target process.
     * @param compiled Pre-compiled pattern.
     * @return Absolute virtual address of match, or 0 if not found.
     */
    uintptr_t pattern_scan(const std::vector<uint8_t>& buffer, uintptr_t base_address, const CompiledPattern& compiled, size_t* match_count = nullptr);

    /**
     * @brief Overload that accepts a raw string pattern.
     */
    uintptr_t pattern_scan(const std::vector<uint8_t>& buffer, uintptr_t base_address, const std::string& pattern);

    /**
     * @brief Resolves a RIP-relative displacement directly from the local memory buffer
     *        WITHOUT issuing kernel ReadProcessMemory calls.
     * @param buffer Read buffer of the module.
     * @param base_address Module base address.
     * @param instruction_address Virtual address of the instruction.
     * @param disp_offset Displacement offset relative to instruction start.
     * @param instruction_size Total size of the instruction.
     * @return Resolved absolute 64-bit virtual address, or 0 on error.
     */
    uintptr_t resolve_rip_local(
        const std::vector<uint8_t>& buffer,
        uintptr_t base_address,
        uintptr_t instruction_address,
        int disp_offset = 3,
        int instruction_size = 7
    );

    /**
     * @brief Reads a 64-bit pointer from the target process.
     */
    uintptr_t dereference_pointer(HANDLE process_handle, uintptr_t address);
}


