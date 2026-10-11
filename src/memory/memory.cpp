#include "memory.hpp"
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace memory {
    CompiledPattern compile_pattern(const std::string& pattern) {
        CompiledPattern cp;
        std::istringstream parser(pattern);
        std::string part;
        while (parser >> part) {
            if (part == "?" || part == "??") {
                cp.elements.push_back({ true, 0 });
            } else {
                size_t consumed = 0;
                auto value = std::stoul(part, &consumed, 16);
                if (part.size() != 2 || consumed != part.size() || value > 255) throw std::invalid_argument("Invalid signature byte");
                uint8_t byte_val = static_cast<uint8_t>(value);
                if (!cp.has_non_wildcard) {
                    cp.has_non_wildcard = true;
                    cp.first_non_wildcard_offset = cp.elements.size();
                    cp.first_non_wildcard_value = byte_val;
                }
                cp.elements.push_back({ false, byte_val });
            }
        }
        return cp;
    }

    uintptr_t pattern_scan(const std::vector<uint8_t>& buffer, uintptr_t base_address, const CompiledPattern& compiled, size_t* match_count) {
        if (match_count) *match_count = 0;
        if (buffer.empty() || compiled.elements.empty()) return 0;

        const size_t sig_len = compiled.elements.size();
        const size_t buffer_size = buffer.size();
        if (buffer_size < sig_len) return 0;

        const size_t max_offset = buffer_size - sig_len;
        const uint8_t* scan_bytes = buffer.data();

        const auto* elements_data = compiled.elements.data();
        const bool has_anchor = compiled.has_non_wildcard;
        const size_t anchor_offset = compiled.first_non_wildcard_offset;
        const uint8_t anchor_val = compiled.first_non_wildcard_value;

        uintptr_t candidate = 0;
        for (size_t pos = 0; pos <= max_offset; ) {
            if (has_anchor) {
                const uint8_t* anchor_ptr = scan_bytes + pos + anchor_offset;
                size_t remaining = max_offset - pos + 1;
                const void* match = std::memchr(anchor_ptr, anchor_val, remaining);
                if (!match) return candidate;

                pos = (static_cast<const uint8_t*>(match) - scan_bytes) - anchor_offset;
                if (pos > max_offset) return 0;
            }

            bool matched = true;
            for (size_t i = 0; i < sig_len; ++i) {
                if (!elements_data[i].is_wildcard && elements_data[i].value != scan_bytes[pos + i]) {
                    matched = false;
                    break;
                }
            }

            if (matched && !compiled.code_ranges.empty()) {
                bool executable = false;
                for (const auto& range : compiled.code_ranges)
                    if (pos >= range.first && pos <= range.second && sig_len <= range.second-pos) { executable = true; break; }
                matched = executable;
            }
            if (matched) {
                if (match_count) ++*match_count;
                if (!compiled.unique_only) return base_address + pos;
                if (candidate) return 0;
                candidate = base_address + pos;
            }

            ++pos;
        }

        return candidate;
    }

    uintptr_t pattern_scan(const std::vector<uint8_t>& buffer, uintptr_t base_address, const std::string& pattern) {
        return pattern_scan(buffer, base_address, compile_pattern(pattern));
    }

    uintptr_t resolve_rip_local(
        const std::vector<uint8_t>& buffer,
        uintptr_t base_address,
        uintptr_t instruction_address,
        int disp_offset,
        int instruction_size
    ) {
        if (instruction_address < base_address || disp_offset < 0 || instruction_size <= 0) return 0;
        size_t offset_in_buf = static_cast<size_t>(instruction_address - base_address);
        
        if (offset_in_buf + static_cast<size_t>(disp_offset) + sizeof(int32_t) > buffer.size()) {
            return 0;
        }

        int32_t displacement = 0;
        std::memcpy(&displacement, buffer.data() + offset_in_buf + disp_offset, sizeof(int32_t));

        return instruction_address + instruction_size + displacement;
    }

    uintptr_t dereference_pointer(HANDLE process_handle, uintptr_t address) {
        if (!process_handle || !address) return 0;
        uintptr_t target = 0;
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address), &target, sizeof(target), &bytes_read) ||
            bytes_read != sizeof(target)) {
            return 0;
        }
        return target;
    }
}





