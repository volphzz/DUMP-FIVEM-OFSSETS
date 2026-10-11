#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <thread>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <future>
#include <mutex>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include "process/process.hpp"
#include "memory/memory.hpp"
#include "utils/utils.hpp"

enum class PatternType {
    RIP_RELATIVE,       // 7 bytes long, offset at 3 (e.g. 48 8B 05)
    RIP_RELATIVE_CALL,  // 5 bytes long, offset at 1 (e.g. E8)
    INSTRUCTION         // Exact address of the pattern match
};

struct PatternDefinition {
    const char* category;
    const char* name;
    const char* signature;
    PatternType type;
    int extra_offset;
};

struct DumpResult {
    std::string category;
    std::string name;
    uintptr_t offset;
    bool found;
    size_t matches = 0;
    std::string status = "missing_signature";
};

void print_banner() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hOut, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Cyan
    std::cout << "\n                 Vxz F-DUMPER\n\n";
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); // Violet / Magenta
    std::cout << "                 >> Vxz F-DUMPER | High-Performance Pattern Engine <<\n";
    std::cout << "                 >> Multithreaded Memory Extraction & Multi-Format Exporter <<\n\n";

    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // Reset
}

static const PatternDefinition g_patterns[] = {
    // ── Base Pointers ────────────────────────────────────────────────────────
    {"Base", "m_World",                  "48 8B 05 ? ? ? ? 33 D2 48 8B 40 08 8A CA 48 85 C0 74 16 48 8B",                  PatternType::RIP_RELATIVE,      0},
    {"Base", "m_ReplayInterFace",        "48 8D 0D ? ? ? ? 48 ? ? E8 ? ? ? ? 48 8D 0D ? ? ? ? 8A D8 E8 ? ? ? ? 84 DB 75 13", PatternType::RIP_RELATIVE,   0},
    {"Base", "m_ViewPort",               "48 8B 15 ? ? ? ? 48 8D 2D ? ? ? ? 48 8B CD",                                     PatternType::RIP_RELATIVE,      0},
    {"Base", "m_BlipList",               "4C 8D 05 ? ? ? ? 0F B7 C1",                                                      PatternType::RIP_RELATIVE,      0},
    {"Base", "m_CamGameplayDirector",    "4C 8B 35 ? ? ? ? 33 FF 32 DB",                                                   PatternType::RIP_RELATIVE,      0},

    // ── Script / Native Infrastructure ──────────────────────────────────────
    {"Script", "m_NativeRegistrations",  "48 8D 0D ? ? ? ? 48 8B 14 FA E8 ? ? ? ? 48 85 C0 75 0A",                         PatternType::RIP_RELATIVE,      0},
    {"Script", "m_ScriptThreads",        "45 33 C9 4C 8B 05 ? ? ? ? 4D 85 C0 74 ? 4D 8B 08",                              PatternType::RIP_RELATIVE,      3},
    {"Script", "m_ScriptProgramTable",   "4C 8B 05 ? ? ? ? 40 8A F2 8B E9",                                                PatternType::RIP_RELATIVE,      0},
    {"Script", "m_GlobalPtrTable",       "4C 8D 05 ? ? ? ? 4D 8B 08 4D 85 C9 74 11",                                      PatternType::RIP_RELATIVE,      0},
    {"Script", "m_RunScriptThreads",     "48 89 5C 24 ? 57 48 83 EC 20 80 3D ? ? ? ? ? 48 8B FA 48 8B D9",                PatternType::INSTRUCTION,       0},
    {"Script", "m_NativeInvoker",        "48 8B C4 48 89 58 08 48 89 70 18 4C 89 40 18 55 57 41 55 41 56 41 57 48 8D A8", PatternType::INSTRUCTION,       0},

    // ── Player / Ped ─────────────────────────────────────────────────────────
    {"Ped", "m_LocalPlayer",            "48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 85 C0 74 ? 48 8B 40 ? C3",    PatternType::RIP_RELATIVE,      0},
    {"Ped", "m_PedList",                "48 8B 05 ? ? ? ? 8B 78 10 85 FF",                                                PatternType::RIP_RELATIVE,      0},
    {"Ped", "m_PedFactory",             "48 8B 05 ? ? ? ? 8B CF FF 50 ? 48 85 C0",                                        PatternType::RIP_RELATIVE,      0},
    {"Ped", "m_SetPedHealth",           "F3 0F 11 81 ? ? ? ? 0F 28 74 24 ? 0F 28 7C 24",                                  PatternType::INSTRUCTION,       0},
    {"Ped", "m_SetPedArmour",           "C7 81 ? ? ? ? ? ? ? ? 74 ? 48 8B CB E8",                                         PatternType::INSTRUCTION,       0},
    {"Ped", "m_SetPedMaxHealth",        "66 89 81 ? ? ? ? 48 8B 01 FF 50 ? 84 C0",                                        PatternType::INSTRUCTION,       0},
    {"Ped", "m_FriendlyFire",           "38 05 ? ? ? ? 0F 85 ? ? ? ? 48 8D 4C 24",                                         PatternType::INSTRUCTION,       0},
    {"Ped", "m_WantedLevelPtr",         "8A D9 48 8D 0D ? ? ? ? E8 ? ? ? ? 84 C0",                                        PatternType::RIP_RELATIVE,      2},
    {"Ped", "m_ClearWanted",            "40 53 48 83 EC 20 48 8B 59 70 48 85 DB 74 ? E8",                                 PatternType::INSTRUCTION,       0},
    {"Ped", "m_SetRunSpeed",            "F3 0F 11 83 ? ? ? ? F3 0F 59 C9 F3 0F 11 4B",                                    PatternType::INSTRUCTION,       0},

    // ── Weapons / Combat ─────────────────────────────────────────────────────
    {"Weapon", "m_GiveWeapon",          "48 89 5c 24 ? 48 89 6c 24 ? 48 89 74 24 ? 57 48 83 ec ? 41 8b f0 8b fa 48 8b d9 e8", PatternType::INSTRUCTION,  0},
    {"Weapon", "m_RemoveWeapon",        "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B D9 41 8B F8",                   PatternType::INSTRUCTION,       0},
    {"Weapon", "m_SilentAim",           "48 8D 45 ? F3 0F 10 00 F3 0F 10 48 ? F3 0F 11 45",                                PatternType::INSTRUCTION,       0},
    {"Weapon", "m_InfiniteAmmo0",       "41 2B C9 3B C8 0F 4D C8",                                                         PatternType::INSTRUCTION,       0},
    {"Weapon", "m_InfiniteAmmo1",       "41 2B D1 E8",                                                                     PatternType::INSTRUCTION,       0},
    {"Weapon", "m_MagicBulletsPatch",   "0F 29 4F ? 83 8F ? ? ? ? ? 48 8B 4F",                                             PatternType::INSTRUCTION,       0},
    {"Weapon", "m_Spread",              "F3 41 0F 10 B0 ? ? ? ? 48 8B CA",                                                PatternType::INSTRUCTION,       0},
    {"Weapon", "m_Recoil",              "F3 0F 10 B0 ? ? ? ? 49 8B 87",                                                   PatternType::INSTRUCTION,       0},
    {"Weapon", "m_CWeapon",             "48 8B 8B ? ? ? ? 48 8B D7 E8 ? ? ? ? 48 8B 8B ? ? ? ? 48 8B D7 E8",              PatternType::INSTRUCTION,       0},
    {"Weapon", "m_WeaponDamage",        "F3 0F 59 05 ? ? ? ? F3 0F 58 C1",                                                 PatternType::INSTRUCTION,       0},
    {"Weapon", "m_BulletImpact",        "F3 0F 10 05 ? ? ? ? F3 0F 58 45 ? F3 0F 11 45",                                   PatternType::INSTRUCTION,       0},
    {"Weapon", "bullet",                "F3 41 0F 10 19 F3 41 0F 10 41 04",                                               PatternType::INSTRUCTION,       0},

    // ── Vehicle ───────────────────────────────────────────────────────────────
    {"Vehicle", "m_VehicleEngineHealth",    "F3 0F 11 80 ? ? ? ? 48 8B 87 ? ? ? ? F3 0F 10 05",                           PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_VehicleDriver",          "4C 8B 94 C7 ? ? ? ? EB ? 4D 8B D6 41 8A 82",                                 PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_VehicleDoorsLockState",  "74 ? 83 B9 ? ? ? ? ? 75 ? 45 84 F6",                                         PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_Handling",               "48 8B 83 ? ? ? ? 8B D5 48 89 44 24 ? 4C 89 74 24",                           PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_Speed",                  "0F 2F C2 77 ? F3 0F 10 83 ? ? ? ? 48 83 C4",                                 PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_SeatBealt",              "F6 81 ? ? ? ? ? 75 ? 8B 83",                                                  PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_VehicleList",            "48 8B 05 ? ? ? ? 0F B7 48 10 48 8B 08",                                      PatternType::RIP_RELATIVE,      0},
    {"Vehicle", "m_SetVehicleGravity",      "F3 0F 11 83 ? ? ? ? 48 8B 8B ? ? ? ? 48 85 C9 74",                           PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_VehicleBoost",           "F3 0F 11 8B ? ? ? ? 48 8B 83 ? ? ? ? 48 85 C0",                              PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_VehicleGravityMultiplier","F3 0F 10 83 ? ? ? ? F3 0F 59 05 ? ? ? ? F3 0F 11 83",                        PatternType::INSTRUCTION,       0},
    {"Vehicle", "m_RequestVehicle",         "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B DA 48 8B F9 E8 ? ? ? ? 84 C0 74", PatternType::INSTRUCTION, 0},
    {"Vehicle", "set_ped_in_to_vehicle",    "48 8B C4 44 89 48 ? 44 89 40 ? 48 89 50 ? 48 89 48 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 83 BA", PatternType::INSTRUCTION, 0},

    // ── Kinematics / Physics ─────────────────────────────────────────────────
    {"Physics", "m_ArmsKinematics",         "E8 ? ? ? ? 48 83 C3 60 48 FF CF 75 E6 48 8B 5C 24",                           PatternType::RIP_RELATIVE_CALL, 0},
    {"Physics", "m_LegsKinematics",         "E8 ? ? ? ? 48 83 C3 60 48 FF CF 75 DF 48 8B 5C 24 ? 48 8B 6C 24 ? 48 8B 74 24", PatternType::RIP_RELATIVE_CALL, 0},
    {"Physics", "m_InfiniteCombatRoll",     "89 81 ? ? ? ? 8B 87 ? ? ? ? F7 D0",                                          PatternType::INSTRUCTION,       0},
    {"Physics", "m_NoRagDoll",              "8B 81 ? ? ? ? 83 E0 ? C1 E0 ? 3D ? ? ? ? 0F 8F",                             PatternType::INSTRUCTION,       0},
    {"Physics", "m_Gravity",                "F3 0F 11 05 ? ? ? ? 0F 28 05 ? ? ? ?",                                       PatternType::RIP_RELATIVE,      0},

    // ── Network / Session ────────────────────────────────────────────────────
    {"Network", "m_NetworkPlayerMgr",       "48 8B 0D ? ? ? ? 8A C3 48 8B 01 FF 50",                                      PatternType::RIP_RELATIVE,      0},
    {"Network", "m_NetGamePlayer",          "48 8B 0D ? ? ? ? 8A D3 E8 ? ? ? ? 48 8B D8",                                 PatternType::RIP_RELATIVE,      0},
    {"Network", "m_NetworkPlayerCount",     "8B 0D ? ? ? ? 85 C9 7E ? 48 8B",                                             PatternType::RIP_RELATIVE,      0},
    {"Network", "m_SendClonedCreate",       "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 30 48 8B FA", PatternType::INSTRUCTION, 0},
    {"Network", "m_NetworkObjectMgr",       "48 8B 0D ? ? ? ? 45 33 C9 45 33 C0 48 8B 01",                               PatternType::RIP_RELATIVE,      0},
    {"Network", "m_GetNetworkObject",       "48 89 5C 24 ? 57 48 83 EC 20 8B DA 48 8B F9 E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8", PatternType::INSTRUCTION, 0},

    // ── Rendering / Camera ───────────────────────────────────────────────────
    {"Render", "m_CObject",                "4C 8B 41 ? 4D 85 C9",                                                         PatternType::INSTRUCTION,       0},
    {"Render", "m_OffsetPool",             "0F B7 CA 83 F9 07 7F 5E",                                                     PatternType::INSTRUCTION,       0},
    {"Render", "m_WorldToScreen",          "48 89 5C 24 ? 55 56 57 48 83 EC 70 48 8B 05 ? ? ? ? 48 8B F9",               PatternType::INSTRUCTION,       0},
    {"Render", "m_CamMatrix",              "48 8D 0D ? ? ? ? F3 0F 10 05 ? ? ? ? F3 0F 11 01",                           PatternType::RIP_RELATIVE,      0},
    {"Render", "c_sky_settings",           "48 8D 0D ? ? ? ? E8 ? ? ? ? 83 25 ? ? ? ? 00 48 8D 0D ? ? ? ? F3",          PatternType::RIP_RELATIVE,      0},

    // ── Entity / Object Pools ────────────────────────────────────────────────
    {"Pools", "m_EntityPool",             "48 8B 05 ? ? ? ? 41 0F BF C8 0F BF 40",                                       PatternType::RIP_RELATIVE,      0},
    {"Pools", "m_ObjectPool",             "48 8B 05 ? ? ? ? 8B 40 10 85 C0 74 38",                                       PatternType::RIP_RELATIVE,      0},
    {"Pools", "m_PickupPool",             "48 8B 05 ? ? ? ? 8B 40 10 85 C0 74 ? 48 8B 0D",                               PatternType::RIP_RELATIVE,      0},
    {"Pools", "m_GetEntityFromHandle",    "83 F9 FF 74 31 4C 8B 0D ? ? ? ? 44 8B C1 49 8B 41 08",                        PatternType::INSTRUCTION,       0},

    // ── World / Misc ──────────────────────────────────────────────────────────
    {"Misc", "aim_cped",                 "48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 85 C9 74 05 E8 ? ? ? ? 8A CB", PatternType::RIP_RELATIVE,      0},
    {"Misc", "m_FreezeTime",             "83 3D ? ? ? ? ? 75 ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 0D",                    PatternType::INSTRUCTION,       0},
    {"Misc", "m_SetEntityCoords",        "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 0F 29 74 24 ? 48 8B F9 0F 28 F2",  PatternType::INSTRUCTION,       0},
    {"Misc", "m_GetEntityCoords",        "E8 ? ? ? ? 0F 28 00 0F 29 44 24 ? 48 8B 4C 24",                                PatternType::RIP_RELATIVE_CALL, 0},
    {"Misc", "m_GameFrameCounter",       "8B 05 ? ? ? ? 8B 0D ? ? ? ? 03 C8",                                             PatternType::INSTRUCTION,       0},
    {"Misc", "m_TimerA",                 "8B 15 ? ? ? ? 48 8B 05 ? ? ? ? 48 85 C0",                                      PatternType::INSTRUCTION,       0},
    {"Misc", "m_TimerB",                 "89 0D ? ? ? ? 8B 0D ? ? ? ? 85 C9 74",                                         PatternType::INSTRUCTION,       0},
};

// ── Export Generators ────────────────────────────────────────────────────────

void export_json(const std::vector<DumpResult>& results, int build, const std::string& filename = "offsets.json") {
    std::ofstream file(filename);
    if (!file.is_open()) throw std::runtime_error("Cannot create export: " + filename);
    file.exceptions(std::ios::badbit | std::ios::failbit);

    file << "{\n";
    file << "  \"engine\": \"Vxz F-DUMPER\",\n";
    file << "  \"build\": " << build << ",\n";
    file << "  \"offsets\": {\n";

    bool first = true;
    for (const auto& r : results) {
        if (!r.found) continue;
        if (!first) file << ",\n";
        file << "    \"" << r.name << "\": " << r.offset;
        first = false;
    }
    file << "\n  }\n}\n";
    logger::log("Exported -> " + filename, logger::success);
}

void export_hpp(const std::vector<DumpResult>& results, int build, const std::string& filename = "offsets.hpp") {
    std::ofstream file(filename);
    if (!file.is_open()) throw std::runtime_error("Cannot create export: " + filename);
    file.exceptions(std::ios::badbit | std::ios::failbit);

    file << "#pragma once\n";
    file << "// Generated by Vxz F-DUMPER\n";
    file << "// Target Build: " << build << "\n";
    file << "#include <cstdint>\n#include <cstddef>\n\n";
    file << "namespace vzx::offsets {\n";

    for (const auto& r : results) {
        if (!r.found) continue;
        file << "    constexpr std::ptrdiff_t " << r.name << " = 0x" 
             << std::hex << std::uppercase << r.offset << ";\n";
    }

    file << "}\n";
    logger::log("Exported -> " + filename, logger::success);
}

void export_cs(const std::vector<DumpResult>& results, int build, const std::string& filename = "offsets.cs") {
    std::ofstream file(filename);
    if (!file.is_open()) throw std::runtime_error("Cannot create export: " + filename);
    file.exceptions(std::ios::badbit | std::ios::failbit);

    file << "// Generated by Vxz F-DUMPER\n";
    file << "// Target Build: " << build << "\n";
    file << "namespace Vxz.Offsets\n{\n";
    file << "    public static class GameOffsets\n    {\n";

    for (const auto& r : results) {
        if (!r.found) continue;
        file << "        public const long " << r.name << " = 0x" 
             << std::hex << std::uppercase << r.offset << ";\n";
    }

    file << "    }\n}\n";
    logger::log("Exported -> " + filename, logger::success);
}

void export_rust(const std::vector<DumpResult>& results, int build, const std::string& filename = "offsets.rs") {
    std::ofstream file(filename);
    if (!file.is_open()) throw std::runtime_error("Cannot create export: " + filename);
    file.exceptions(std::ios::badbit | std::ios::failbit);

    file << "// Generated by Vxz F-DUMPER\n";
    file << "// Target Build: " << build << "\n";
    file << "pub mod offsets {\n";

    for (const auto& r : results) {
        if (!r.found) continue;
        file << "    pub const " << r.name << ": usize = 0x" 
             << std::hex << std::uppercase << r.offset << ";\n";
    }

    file << "}\n";
    logger::log("Exported -> " + filename, logger::success);
}

void export_cheat_table(const std::vector<DumpResult>& results, int build, const std::string& filename = "offsets.CT") {
    std::ofstream file(filename);
    if (!file.is_open()) throw std::runtime_error("Cannot create export: " + filename);
    file.exceptions(std::ios::badbit | std::ios::failbit);

    file << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    file << "<CheatTable CheatEngineTableVersion=\"45\">\n";
    file << "  <CheatEntries>\n";

    int id = 0;
    for (const auto& r : results) {
        if (!r.found) continue;
        file << "    <CheatEntry>\n";
        file << "      <ID>" << id++ << "</ID>\n";
        file << "      <Description>\"" << r.name << "\"</Description>\n";
        file << "      <ShowAsHex>1</ShowAsHex>\n";
        file << "      <VariableType>8 Bytes</VariableType>\n";
        file << "      <Address>\"FiveM_b" << build << "_GTAProcess.exe\"+0x" 
             << std::hex << std::uppercase << r.offset << "</Address>\n";
        file << "    </CheatEntry>\n";
    }

    file << "  </CheatEntries>\n";
    file << "</CheatTable>\n";
    logger::log("Exported -> " + filename, logger::success);
}

bool load_module_image(const std::filesystem::path& path, std::vector<uint8_t>& buffer) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    const auto size = file.tellg();
    if (size <= 0) return false;
    buffer.resize(static_cast<size_t>(size));
    file.seekg(0);
    return static_cast<bool>(file.read(reinterpret_cast<char*>(buffer.data()), size));
}

// ── Main Entry Point ─────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    SetConsoleTitleA("Vxz F-DUMPER - Next-Gen FiveM Offsets Dumper");

    HWND console = GetConsoleWindow();
    if (console) {
        LONG style = GetWindowLong(console, GWL_STYLE);
        style |= WS_OVERLAPPEDWINDOW;
        SetWindowLong(console, GWL_STYLE, style);
    }

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    SetConsoleOutputCP(CP_UTF8);

    if (argc > 1 && std::string(argv[1]) == "--self-test") {
        const uintptr_t base = 0x1000;
        std::vector<uint8_t> bytes{0x90,0x48,0x8B,0x05,0xF8,0xFF,0xFF,0xFF};
        bool ok = memory::pattern_scan(bytes, base, "48 8B 05 ?? ?? ?? ??") == base+1
            && memory::pattern_scan(bytes, base, "FF FF") == base+5
            && memory::pattern_scan(bytes, base, "AA BB") == 0
            && memory::resolve_rip_local(bytes, base, base+1, 3, 7) == base
            && memory::resolve_rip_local(bytes, base, base+6, 3, 7) == 0;
        auto last = memory::compile_pattern("48 8B 05 ?? ?? ?? ??"); last.unique_only = true;
        ok = ok && memory::pattern_scan(bytes, base, last) == base+1;
        auto unique = memory::compile_pattern("FF FF"); unique.unique_only = true;
        ok = ok && memory::pattern_scan(bytes, base, unique) == 0;
        size_t count = 0;
        ok = ok && memory::pattern_scan(bytes, base, unique, &count) == 0 && count == 2;
        unique.code_ranges = {{6,8}};
        ok = ok && memory::pattern_scan(bytes, base, unique, &count) == base+6 && count == 1;
        unique.code_ranges = {{0,6}};
        ok = ok && memory::pattern_scan(bytes, base, unique, &count) == 0 && count == 0;
        try { memory::compile_pattern("123"); ok = false; } catch (const std::exception&) {}
        std::cout << (ok ? "Self-test PASS\n" : "Self-test FAIL\n");
        return ok ? 0 : 1;
    }
    const bool offline = argc == 6 && std::string(argv[1]) == "--offline";
    if (argc > 1 && !offline && argc != 2) {
        std::cerr << "Usage: Vxz F-DUMPER.exe [export-directory] | --offline <module.bin> <module-base-hex> <build> <export-directory>\n";
        return 1;
    }
    print_banner();
    std::filesystem::path output = offline ? argv[5] : (argc > 1 ? argv[1] : "exports");
    std::filesystem::create_directories(output);
    std::filesystem::current_path(output);
    process::ProcessTarget target;
    std::vector<uint8_t> module_buffer;
    HANDLE process_handle = nullptr;
    if (offline) {
        try {
            target.base_address = std::stoull(argv[3], nullptr, 0);
            target.build = std::stoi(argv[4]);
        } catch (...) {
            logger::log("Invalid offline base address or build number.", logger::fail);
            return 1;
        }
        target.name = "offline-module";
        if (!load_module_image(argv[2], module_buffer)) {
            logger::log("Could not read offline module image.", logger::fail);
            return 1;
        }
        target.module_size = static_cast<DWORD>(module_buffer.size());
        logger::log("Offline module loaded: " + std::to_string(module_buffer.size() / (1024 * 1024)) + " MB", logger::success);
    } else {
        logger::log("Waiting for FiveM / GTA process...", logger::info);
        while (true) {
            target = process::find_fivem_process();
            if (target.pid != 0 && target.base_address != 0 && target.module_size != 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        }
        process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
        if (!process_handle || !process::dump_module_buffer(process_handle, target.base_address, target.module_size, module_buffer)) {
            logger::log("Failed to mirror process module.", logger::fail);
            if (process_handle) CloseHandle(process_handle);
            return 1;
        }
    }

    // ── High-Speed Parallel Pattern Resolution ───────────────────────────────
    logger::log("Executing parallel signature scan across CPU cores...", logger::info);
    auto scan_start = std::chrono::high_resolution_clock::now();

    const size_t total_patterns = sizeof(g_patterns) / sizeof(g_patterns[0]);
    std::vector<DumpResult> results(total_patterns);

    // Restrict instruction signatures to executable PE sections.
    std::vector<std::pair<size_t, size_t>> code_ranges;
    if (module_buffer.size() < sizeof(IMAGE_DOS_HEADER)) { if (process_handle) CloseHandle(process_handle); return 3; }
    IMAGE_DOS_HEADER dos{}; std::memcpy(&dos, module_buffer.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
        size_t(dos.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > module_buffer.size()) { if (process_handle) CloseHandle(process_handle); return 3; }
    IMAGE_NT_HEADERS64 nt{}; std::memcpy(&nt, module_buffer.data()+dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { if (process_handle) CloseHandle(process_handle); return 3; }
    size_t section_offset = size_t(dos.e_lfanew)+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt.FileHeader.SizeOfOptionalHeader;
    for (size_t i=0; i<nt.FileHeader.NumberOfSections; ++i) {
        if (section_offset > module_buffer.size() || sizeof(IMAGE_SECTION_HEADER) > module_buffer.size()-section_offset) break;
        IMAGE_SECTION_HEADER section{}; std::memcpy(&section, module_buffer.data()+section_offset, sizeof(section));
        section_offset += sizeof(section);
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            size_t begin=section.VirtualAddress, end=std::min(module_buffer.size(), begin+size_t(section.Misc.VirtualSize));
            if (begin<end) code_ranges.emplace_back(begin,end);
        }
    }
    if (code_ranges.empty()) { if (process_handle) CloseHandle(process_handle); return 3; }
    logger::log("Scanning executable sections: " + std::to_string(code_ranges.size()), logger::info);
    // Precompile pattern structures
    std::vector<memory::CompiledPattern> compiled_patterns;
    compiled_patterns.reserve(total_patterns);
    for (size_t i = 0; i < total_patterns; ++i) {
        compiled_patterns.push_back(memory::compile_pattern(g_patterns[i].signature));
        compiled_patterns.back().unique_only = true;
        compiled_patterns.back().code_ranges = code_ranges;
    }

    // Parallel dispatch using std::async across thread chunks
    const unsigned int hardware_threads = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::future<void>> futures;
    size_t chunk_size = (total_patterns + hardware_threads - 1) / hardware_threads;

    for (unsigned int t = 0; t < hardware_threads; ++t) {
        size_t start_idx = t * chunk_size;
        size_t end_idx = std::min(start_idx + chunk_size, total_patterns);
        if (start_idx >= total_patterns) break;

        futures.push_back(std::async(std::launch::async, [&, start_idx, end_idx]() {
            for (size_t i = start_idx; i < end_idx; ++i) {
                const auto& pat = g_patterns[i];
                results[i].category = pat.category;
                results[i].name = pat.name;
                results[i].found = false;

                uintptr_t match_addr = memory::pattern_scan(module_buffer, target.base_address, compiled_patterns[i], &results[i].matches);
                if (!match_addr) {
                    if (results[i].matches > 1) results[i].status = "ambiguous_signature";
                    continue;
                }
                results[i].status = "target_outside_module";

                match_addr += pat.extra_offset;

                uintptr_t resolved = 0;
                switch (pat.type) {
                case PatternType::RIP_RELATIVE:
                    resolved = memory::resolve_rip_local(module_buffer, target.base_address, match_addr, (pat.name == std::string("m_Gravity")) ? 4 : (pat.name == std::string("m_NetworkPlayerCount")) ? 2 : 3, (pat.name == std::string("m_Gravity")) ? 8 : (pat.name == std::string("m_NetworkPlayerCount")) ? 6 : 7);
                    break;
                case PatternType::RIP_RELATIVE_CALL:
                    resolved = memory::resolve_rip_local(module_buffer, target.base_address, match_addr, 1, 5);
                    break;
                case PatternType::INSTRUCTION:
                    resolved = match_addr;
                    break;
                }

                if (resolved >= target.base_address && resolved < target.base_address + target.module_size) {
                    results[i].offset = resolved - target.base_address;
                    results[i].found = true;
                    results[i].status = "matched_unverified";
                }
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }

    auto scan_end = std::chrono::high_resolution_clock::now();
    auto scan_ms = std::chrono::duration_cast<std::chrono::milliseconds>(scan_end - scan_start).count();

    std::cout << "\n";
    int found_count = 0;
    for (const auto& r : results) {
        if (r.found) {
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << r.offset;
            logger::log(r.name + " -> 0x" + ss.str(), logger::success);
            found_count++;
        } else {
            logger::log(r.name + " -> [" + r.status + "]", logger::warn);
        }
    }

    std::cout << "\n";
    logger::log("Scan completed in " + std::to_string(scan_ms) + " ms (" + std::to_string(hardware_threads) + " threads)", logger::info);
    logger::log("Resolved " + std::to_string(found_count) + " / " + std::to_string(total_patterns) + " patterns.", logger::info);
    std::cout << "\n";

    std::ofstream report("scan-report.csv");
    report.exceptions(std::ios::badbit | std::ios::failbit);
    report << "category,name,status,rva,absolute_address,kind,matches_minimum\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        report << r.category << ',' << r.name << ',' << r.status << ',';
        if (r.found) {
            report << "0x" << std::hex << r.offset;
            report << ",0x" << (target.base_address + r.offset) << std::dec;
        } else {
            report << ',';
        }
        report << ',' << (g_patterns[i].type == PatternType::INSTRUCTION ? "instruction_address" : "rip_target_address") << ',' << r.matches << '\n';
    }
    report.close();
    if (!found_count) { if (process_handle) CloseHandle(process_handle); return 2; }
    // ── Multi-Format Exports ─────────────────────────────────────────────────
    export_json(results, target.build, "offsets.json");
    export_hpp(results, target.build, "offsets.hpp");
    export_cs(results, target.build, "offsets.cs");
    export_rust(results, target.build, "offsets.rs");
    export_cheat_table(results, target.build, "offsets.CT");

    if (process_handle) CloseHandle(process_handle);
    std::cout << "\n";
    logger::log("Dump completed. Exports saved.", logger::info);
    if (argc == 1) std::cin.get();
    return 0;
}






