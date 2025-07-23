#include <windows.h>
#include <Psapi.h>
#include <ShObjIdl.h>
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <dwarf.h>
#include <libdwarf.h>
#include "bridgemain.h"
#include "_plugins.h"

#include "_scriptapi_argument.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_bookmark.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_flag.h"
#include "_scriptapi_function.h"
#include "_scriptapi_gui.h"
#include "_scriptapi_label.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_misc.h"
#include "_scriptapi_module.h"
#include "_scriptapi_pattern.h"
#include "_scriptapi_register.h"
#include "_scriptapi_stack.h"
#include "_scriptapi_symbol.h"

#include "DeviceNameResolver/DeviceNameResolver.h"
#include "jansson/jansson.h"
#include "lz4/lz4file.h"
#include "TitanEngine/TitanEngine.h"
#include "XEDParse/XEDParse.h"

#ifdef _WIN64
#pragma comment(lib, "x64dbg.lib")
#pragma comment(lib, "x64bridge.lib")
#pragma comment(lib, "DeviceNameResolver/DeviceNameResolver_x64.lib")
#pragma comment(lib, "jansson/jansson_x64.lib")
#pragma comment(lib, "lz4/lz4_x64.lib")
#pragma comment(lib, "TitanEngine/TitanEngine_x64.lib")
#pragma comment(lib, "XEDParse/XEDParse_x64.lib")
#pragma comment(lib, "libdwarf_x64.lib")
#else
#pragma comment(lib, "x32dbg.lib")
#pragma comment(lib, "x32bridge.lib")
#pragma comment(lib, "DeviceNameResolver/DeviceNameResolver_x86.lib")
#pragma comment(lib, "jansson/jansson_x86.lib")
#pragma comment(lib, "lz4/lz4_x86.lib")
#pragma comment(lib, "TitanEngine/TitanEngine_x86.lib")
#pragma comment(lib, "XEDParse/XEDParse_x86.lib")
#pragma comment(lib, "libdwarf_x86.lib")
#endif //_WIN64

// Plugin SDK definitions
#define PLUGIN_NAME "DWARFHelper"
#define PLUGIN_VERSION 1
#define DEBUG
#ifdef DEBUG
#define DPRINTF(x, ...) _plugin_logprintf("[" PLUGIN_NAME "] " x "\n", __VA_ARGS__)
#define DPUTS(x) _plugin_logprintf("[" PLUGIN_NAME "] %s\n", x)
#else
#define DPRINTF(x, ...)
#define DPUTS(x)
#endif

#define PLUG_EXPORT extern "C" __declspec(dllexport)
static int pluginHandle;
static HWND hwndDlg;
static int menuHandleLabelsDWARF;
static int menuHandleAbout;

// Menu entry IDs
enum MenuAction
{
    MA_LABELS_DWARF = 1001,
    MA_ABOUT = 1004
};

// Structure to hold symbol information
struct TypeInfo
{
    std::string name;
    duint size;
    std::string encoding;             // int, float, pointer, etc.
    duint baseTypeOffset;             // For pointers, arrays
    std::vector<std::string> members; // For structs/unions
};

struct LocationInfo
{
    enum Type
    {
        INVALID,
        ADDRESS,
        REGISTER,
        STACK_OFFSET,
        EXPRESSION
    };
    Type type;
    duint address;
    int reg;
    int offset;
    std::vector<uint8_t> expression; // For complex expressions
};

struct Symbol
{
    std::string name;
    duint address;
    bool isFunction;
    duint size;
    duint endAddress;
    std::string fileName;
    std::string type;
    LocationInfo location;
    std::string compDir;     // Compilation directory
    int line;                // Line number where declared
    bool isExternal;         // External symbol
    std::string linkageName; // Mangled name
};

// Structure to hold line information
struct LineInfo
{
    std::string file;
    unsigned int line;
    duint address;
};

// Global maps for types and compilation directories
static std::map<Dwarf_Off, TypeInfo> g_typeMap;
static std::map<std::string, std::string> g_compDirMap;

struct AddressCache
{
    std::unordered_map<duint, duint> dwarfToRuntime;
    duint imageBase;
    duint runtimeBase;
    duint baseOffset;

    void Initialize(duint dwarf_base, duint runtime_base)
    {
        imageBase = dwarf_base;
        runtimeBase = runtime_base;
        baseOffset = runtime_base - dwarf_base;
        dwarfToRuntime.clear();
        DPRINTF("Address cache initialized: DWARF base=0x%llX, Runtime base=0x%llX, Offset=0x%llX",
                dwarf_base, runtime_base, baseOffset);
    }

    duint TranslateAddress(duint dwarf_addr)
    {
        if (imageBase == 0 && runtimeBase == 0)
        {
            return dwarf_addr;
        }

        auto it = dwarfToRuntime.find(dwarf_addr);
        if (it != dwarfToRuntime.end())
        {
            return it->second;
        }

        duint runtime_addr;
        if (imageBase == 0)
        {
            runtime_addr = dwarf_addr + runtimeBase;
        }
        else
        {
            if (dwarf_addr >= imageBase)
            {
                runtime_addr = (dwarf_addr - imageBase) + runtimeBase;
            }
            else
            {
                runtime_addr = dwarf_addr + runtimeBase;
            }
        }

        dwarfToRuntime[dwarf_addr] = runtime_addr;
        DPRINTF("Translated address: 0x%llX -> 0x%llX (imageBase=0x%llX, runtimeBase=0x%llX)",
                dwarf_addr, runtime_addr, imageBase, runtimeBase);
        return runtime_addr;
    }
};

static AddressCache g_addressCache;

// Get current EIP/RIP
duint GetCurrentEIP()
{
    DPUTS("Entering GetCurrentEIP");
    REGDUMP registers;
    if (!DbgIsDebugging())
    {
        DPUTS("DbgIsDebugging returned false");
        return 0;
    }
    if (DbgGetRegDumpEx(&registers, sizeof(REGDUMP)))
    {
        DPRINTF("DbgGetRegDumpEx succeeded, cip = 0x%llX", registers.regcontext.cip);
        if (registers.regcontext.cip == 0)
        {
            DPUTS("Warning: cip is 0, invalid instruction pointer");
        }
        return registers.regcontext.cip;
    }
    DPUTS("DbgGetRegDumpEx failed");
    return 0;
}

// Get base address from the PE
duint GetImageBaseFromHeaders(const void *imageData, size_t imageSize)
{
    if (!imageData || imageSize < sizeof(IMAGE_DOS_HEADER))
    {
        return 0;
    }

    const IMAGE_DOS_HEADER *dosHeader = static_cast<const IMAGE_DOS_HEADER *>(imageData);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DPUTS("Invalid DOS signature");
        return 0;
    }

    if (static_cast<size_t>(dosHeader->e_lfanew) >= imageSize || dosHeader->e_lfanew < 0)
    {
        DPUTS("Invalid PE header offset");
        return 0;
    }

    const IMAGE_NT_HEADERS *ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        static_cast<const char *>(imageData) + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DPUTS("Invalid NT signature");
        return 0;
    }

    duint imageBase = static_cast<duint>(ntHeaders->OptionalHeader.ImageBase);
    DPRINTF("Image base from headers: 0x%llX", imageBase);
    return imageBase;
}

// Get base module address from the x64dbg
static duint GetModuleBase()
{
    duint currentEIP = GetCurrentEIP();
    if (!currentEIP)
        return 0;
        
    char moduleName[MAX_PATH] = "";
    if (!DbgGetModuleAt(currentEIP, moduleName))
        return 0;
        
    auto* dbgFuncs = DbgFunctions();
    if (!dbgFuncs)
        return 0;
        
    return dbgFuncs->ModBaseFromName(moduleName);
}

// Get module size
static duint GetModuleSize(duint moduleBase)
{
    if (!moduleBase)
        return 0;
        
    MODULEINFO modInfo = {0};
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModule = (HMODULE)moduleBase;
    
    if (GetModuleInformation(hProcess, hModule, &modInfo, sizeof(MODULEINFO)))
        return modInfo.SizeOfImage;
        
    return 0;
}

// Get image base from PE headers
static duint GetImageBaseFromPE(const std::filesystem::path& filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
        return 0;
        
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0);
    
    if (fileSize < sizeof(IMAGE_DOS_HEADER))
        return 0;
        
    std::vector<char> buffer(fileSize);
    file.read(buffer.data(), fileSize);
    file.close();
    
    return GetImageBaseFromHeaders(buffer.data(), fileSize);
}



// Validate address within module bounds
static bool IsValidModuleAddress(duint address, duint modBase, duint modSize)
{
    return address >= modBase && address < modBase + modSize;
}

// Utility to clean symbol names for x64dbg compatibility
static std::string CleanSymbolName(const std::string &name)
{
    std::string cleaned = name;
    for (char &c : cleaned)
    {
        if (c == '$' || c == ':' || c == '@' || (!std::isalnum(c) && c != '_'))
        {
            c = '_';
        }
    }
    while (!cleaned.empty() && cleaned.front() == '_')
    {
        cleaned.erase(cleaned.begin());
    }
    while (!cleaned.empty() && cleaned.back() == '_')
    {
        cleaned.pop_back();
    }
    return cleaned.empty() ? "Symbol" : cleaned;
}

// Get function size by analyzing high_pc attribute or searching for next function
static duint GetFunctionSize(Dwarf_Die function_die, Dwarf_Debug dbg, Dwarf_Addr low_pc, Dwarf_Error *error)
{
    duint size = 0;

    Dwarf_Attribute high_pc_attr = 0;
    if (dwarf_attr(function_die, DW_AT_high_pc, &high_pc_attr, error) == DW_DLV_OK)
    {
        Dwarf_Half form = 0;
        if (dwarf_whatform(high_pc_attr, &form, error) == DW_DLV_OK)
        {
            if (form == DW_FORM_addr)
            {
                Dwarf_Addr high_pc = 0;
                if (dwarf_formaddr(high_pc_attr, &high_pc, error) == DW_DLV_OK && high_pc > low_pc)
                {
                    size = high_pc - low_pc;
                }
            }
            else if (form == DW_FORM_data1 || form == DW_FORM_data2 ||
                     form == DW_FORM_data4 || form == DW_FORM_data8 ||
                     form == DW_FORM_udata)
            {
                Dwarf_Unsigned offset = 0;
                if (dwarf_formudata(high_pc_attr, &offset, error) == DW_DLV_OK)
                {
                    size = static_cast<duint>(offset);
                }
            }
        }
        dwarf_dealloc_attribute(high_pc_attr);
    }

    if (size == 0)
    {
        Dwarf_Attribute size_attr = 0;
        if (dwarf_attr(function_die, DW_AT_byte_size, &size_attr, error) == DW_DLV_OK)
        {
            Dwarf_Unsigned size_val = 0;
            if (dwarf_formudata(size_attr, &size_val, error) == DW_DLV_OK)
            {
                size = static_cast<duint>(size_val);
            }
            dwarf_dealloc_attribute(size_attr);
        }
    }

    if (size == 0)
    {
        size = 0x20;
        DPRINTF("Using default size %llu for function at 0x%llX", size, low_pc);
    }

    return size;
}


inline duint RebaseAddress(duint value, duint imageBase, duint runtimeBase)
{
    if (imageBase != runtimeBase)
        return value - imageBase + runtimeBase;
    return value;
}

// Parse COFF symbols from PE file
static void ParseCOFFSymbols(const std::filesystem::path& path, duint runtimeBase, duint imageBase, duint modSize, std::vector<Symbol>& loadedSymbols)
{
    DPUTS("Entering ParseCOFFSymbols");

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        DPUTS("Failed to open file for COFF parsing");
        return;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0);
    std::vector<char> fileData(fileSize);
    file.read(fileData.data(), fileSize);
    file.close();

    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DPUTS("Invalid DOS signature for COFF");
        return;
    }

    const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        fileData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DPUTS("Invalid NT signature for COFF");
        return;
    }

    const IMAGE_FILE_HEADER* fileHeader = &ntHeaders->FileHeader;
    if (fileHeader->NumberOfSymbols == 0 || fileHeader->PointerToSymbolTable == 0)
    {
        DPUTS("No COFF symbols found");
        return;
    }

    const IMAGE_SYMBOL* symbolTable = reinterpret_cast<const IMAGE_SYMBOL*>(
        fileData.data() + fileHeader->PointerToSymbolTable);
    const char* stringTable = fileData.data() + fileHeader->PointerToSymbolTable +
                             fileHeader->NumberOfSymbols * sizeof(IMAGE_SYMBOL);
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);

    std::unordered_set<std::string> existingNames;
    std::unordered_set<duint> existingAddresses;
    for (const auto& sym : loadedSymbols)
    {
        existingNames.insert(sym.name);
        if (sym.address != 0)
            existingAddresses.insert(sym.address);
    }

    int coffSymbolCount = 0;
    for (DWORD i = 0; i < fileHeader->NumberOfSymbols; ++i)
    {
        const IMAGE_SYMBOL& sym = symbolTable[i];
        std::string name;

        // Handle symbol name
        if (sym.N.Name.Short != 0)
        {
            size_t len = 0;
            for (len = 0; len < 8 && sym.N.ShortName[len] != 0; ++len) {}
            name = std::string(reinterpret_cast<const char*>(sym.N.ShortName), len);
        }
        else
        {
            name = stringTable + sym.N.Name.Long;
        }

        // Skip empty names, section names, or compiler-generated symbols
        if (name.empty() || name[0] == '.' || name.find("__") == 0)
        {
            DPRINTF("Skipped COFF symbol %s: invalid or compiler-generated name", name.c_str());
            i += sym.NumberOfAuxSymbols;
            continue;
        }

        // Skip symbols with invalid section numbers
        if (sym.SectionNumber <= 0 || sym.SectionNumber > fileHeader->NumberOfSections)
        {
            DPRINTF("Skipped COFF symbol %s: invalid section number %d", name.c_str(), sym.SectionNumber);
            i += sym.NumberOfAuxSymbols;
            continue;
        }

        // Skip static symbols with zero value
        if (sym.StorageClass == IMAGE_SYM_CLASS_STATIC && sym.Value == 0)
        {
            DPRINTF("Skipped COFF symbol %s: static symbol with zero value", name.c_str());
            i += sym.NumberOfAuxSymbols;
            continue;
        }

        // Calculate virtual address: sym.Value (section offset) + section's VA, then rebase
        const IMAGE_SECTION_HEADER& section = sections[sym.SectionNumber - 1];
        duint sectionVA = section.VirtualAddress + imageBase; // Use imageBase initially
        duint address = RebaseAddress(sym.Value + sectionVA, imageBase, runtimeBase);

        // Validate address against module bounds
        if (modSize > 0 && !IsValidModuleAddress(address, runtimeBase, modSize))
        {
            DPRINTF("Skipped COFF symbol %s: address 0x%llX outside module range", name.c_str(), address);
            i += sym.NumberOfAuxSymbols;
            continue;
        }

        // Skip duplicates
        if (existingNames.count(name) || existingAddresses.count(address))
        {
            DPRINTF("Skipped duplicate COFF symbol %s at 0x%llX", name.c_str(), address);
            i += sym.NumberOfAuxSymbols;
            continue;
        }

        // Determine if symbol is a function
        bool isFunction = (sym.Type & 0x20) != 0 && (section.Characteristics & IMAGE_SCN_MEM_EXECUTE);
        bool isData = !isFunction && (sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL || sym.StorageClass == IMAGE_SYM_CLASS_STATIC);

        // Get section permissions
        std::string permissions;
        permissions += (section.Characteristics & IMAGE_SCN_MEM_READ) ? "R" : "";
        permissions += (section.Characteristics & IMAGE_SCN_MEM_WRITE) ? "W" : "";
        permissions += (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? "E" : "";

        // Create symbol
        Symbol symbol = {
            CleanSymbolName(name),
            address,
            isFunction,
            0, // Size often unavailable in COFF
            address,
            "",
            isFunction ? "function" : "data",
            {LocationInfo::INVALID, 0, 0, 0, {}},
            "",
            0,
            (sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL),
            name
        };

        loadedSymbols.push_back(symbol);
        existingNames.insert(symbol.name);
        existingAddresses.insert(symbol.address);
        coffSymbolCount++;
        DPRINTF("Added COFF symbol: %s at 0x%llX (%s, %s)", symbol.name.c_str(), symbol.address, isFunction ? "function" : "data", permissions.c_str());

        // Skip auxiliary symbols
        i += sym.NumberOfAuxSymbols;
    }

    DPRINTF("ParseCOFFSymbols: Loaded %d COFF symbols", coffSymbolCount);
}

// Process DWARF location expression
LocationInfo ProcessLocationExpression(Dwarf_Debug dbg, Dwarf_Attribute attr, Dwarf_Error *error)
{
    LocationInfo loc = {LocationInfo::INVALID, 0, 0, 0, {}};

    // Try to use the DWARF 5 api
    Dwarf_Loc_Head_c loclist_head = 0;
    Dwarf_Unsigned listlen = 0;

    if (dwarf_get_loclist_c(attr, &loclist_head, &listlen, error) == DW_DLV_OK)
    {
        for (Dwarf_Unsigned i = 0; i < listlen; ++i)
        {
            Dwarf_Small loclist_source = 0;
            Dwarf_Addr lowpc = 0, hipc = 0;
            Dwarf_Unsigned expr_ops_count = 0;
            Dwarf_Locdesc_c locentry = 0;
            Dwarf_Small lle_value = 0;
            Dwarf_Addr rawlowpc = 0, rawhipc = 0;
            Dwarf_Bool debug_addr_unavailable = 0;
            Dwarf_Unsigned locdesc_offset = 0;
            Dwarf_Unsigned dw_expression_offset_out = 0;
            Dwarf_Unsigned dw_entry_len_out = 0;

            if (dwarf_get_locdesc_entry_e(
                    loclist_head, i, &lle_value,
                    &rawlowpc, &rawhipc, &debug_addr_unavailable,
                    &lowpc, &hipc, &expr_ops_count, &locdesc_offset,
                    &locentry, &loclist_source,
                    &dw_expression_offset_out, &dw_entry_len_out,
                    error) == DW_DLV_OK)
            {
                if (expr_ops_count > 0)
                {
                    Dwarf_Small op = 0;
                    Dwarf_Unsigned opd1 = 0, opd2 = 0, opd3 = 0;
                    Dwarf_Unsigned offset_for_branch = 0;

                    if (dwarf_get_location_op_value_c(locentry, 0, &op,
                                                      &opd1, &opd2, &opd3, &offset_for_branch, error) == DW_DLV_OK)
                    {
                        loc.type = LocationInfo::EXPRESSION;
                        loc.expression.push_back(op);

                        switch (op)
                        {
                        case DW_OP_addr:
                            loc.type = LocationInfo::ADDRESS;
                            loc.address = g_addressCache.TranslateAddress(static_cast<duint>(opd1));
                            break;
                        case DW_OP_reg0:
                        case DW_OP_reg1:
                        case DW_OP_reg2:
                        case DW_OP_reg3:
                        case DW_OP_reg4:
                        case DW_OP_reg5:
                        case DW_OP_reg6:
                        case DW_OP_reg7:
                        case DW_OP_reg8:
                        case DW_OP_reg9:
                        case DW_OP_reg10:
                        case DW_OP_reg11:
                        case DW_OP_reg12:
                        case DW_OP_reg13:
                        case DW_OP_reg14:
                        case DW_OP_reg15:
                        case DW_OP_reg16:
                        case DW_OP_reg17:
                        case DW_OP_reg18:
                        case DW_OP_reg19:
                        case DW_OP_reg20:
                        case DW_OP_reg21:
                        case DW_OP_reg22:
                        case DW_OP_reg23:
                        case DW_OP_reg24:
                        case DW_OP_reg25:
                        case DW_OP_reg26:
                        case DW_OP_reg27:
                        case DW_OP_reg28:
                        case DW_OP_reg29:
                        case DW_OP_reg30:
                        case DW_OP_reg31:
                            loc.type = LocationInfo::REGISTER;
                            loc.reg = op - DW_OP_reg0;
                            break;
                        case DW_OP_regx:
                            loc.type = LocationInfo::REGISTER;
                            loc.reg = static_cast<int>(opd1);
                            break;
                        case DW_OP_fbreg:
                            loc.type = LocationInfo::STACK_OFFSET;
                            loc.offset = static_cast<int>(opd1);
                            break;
                        case DW_OP_breg0:
                        case DW_OP_breg1:
                        case DW_OP_breg2:
                        case DW_OP_breg3:
                        case DW_OP_breg4:
                        case DW_OP_breg5:
                        case DW_OP_breg6:
                        case DW_OP_breg7:
                        case DW_OP_breg8:
                        case DW_OP_breg9:
                        case DW_OP_breg10:
                        case DW_OP_breg11:
                        case DW_OP_breg12:
                        case DW_OP_breg13:
                        case DW_OP_breg14:
                        case DW_OP_breg15:
                        case DW_OP_breg16:
                        case DW_OP_breg17:
                        case DW_OP_breg18:
                        case DW_OP_breg19:
                        case DW_OP_breg20:
                        case DW_OP_breg21:
                        case DW_OP_breg22:
                        case DW_OP_breg23:
                        case DW_OP_breg24:
                        case DW_OP_breg25:
                        case DW_OP_breg26:
                        case DW_OP_breg27:
                        case DW_OP_breg28:
                        case DW_OP_breg29:
                        case DW_OP_breg30:
                        case DW_OP_breg31:
                            loc.type = LocationInfo::STACK_OFFSET;
                            loc.reg = op - DW_OP_breg0;
                            loc.offset = static_cast<int>(opd1);
                            break;
                        case DW_OP_bregx:
                            loc.type = LocationInfo::STACK_OFFSET;
                            loc.reg = static_cast<int>(opd1);
                            loc.offset = static_cast<int>(opd2);
                            break;
                        }
                        break;
                    }
                }
            }
        }
        dwarf_dealloc_loc_head_c(loclist_head);
    }
    else
    {
        // Fallback to an old api
        Dwarf_Ptr expr_bytes = 0;
        Dwarf_Unsigned expr_len = 0;

        if (dwarf_formexprloc(attr, &expr_len, &expr_bytes, error) == DW_DLV_OK)
        {
            if (expr_len > 0 && expr_bytes)
            {
                uint8_t *bytes = static_cast<uint8_t *>(expr_bytes);
                loc.expression.assign(bytes, bytes + expr_len);

                uint8_t op = bytes[0];
                loc.type = LocationInfo::EXPRESSION;

                switch (op)
                {
                case DW_OP_addr:
                    if (expr_len >= 1 + sizeof(duint))
                    {
                        duint addr = *reinterpret_cast<duint *>(bytes + 1);
                        loc.type = LocationInfo::ADDRESS;
                        loc.address = g_addressCache.TranslateAddress(addr);
                    }
                    break;
                case DW_OP_fbreg:
                    if (expr_len >= 2)
                    {
                        loc.type = LocationInfo::STACK_OFFSET;
                        loc.offset = static_cast<int8_t>(bytes[1]);
                    }
                    break;
                }
            }
        }
        else
        {
            Dwarf_Block *block = 0;
            if (dwarf_formblock(attr, &block, error) == DW_DLV_OK && block)
            {
                if (block->bl_len > 0 && block->bl_data)
                {
                    uint8_t *bytes = static_cast<uint8_t *>(block->bl_data);
                    loc.expression.assign(bytes, bytes + block->bl_len);

                    uint8_t op = bytes[0];
                    loc.type = LocationInfo::EXPRESSION;

                    switch (op)
                    {
                    case DW_OP_addr:
                        if (block->bl_len >= 1 + sizeof(duint))
                        {
                            duint addr = *reinterpret_cast<duint *>(bytes + 1);
                            loc.type = LocationInfo::ADDRESS;
                            loc.address = g_addressCache.TranslateAddress(addr);
                        }
                        break;
                    case DW_OP_fbreg:
                        if (block->bl_len >= 2)
                        {
                            loc.type = LocationInfo::STACK_OFFSET;
                            loc.offset = static_cast<int8_t>(bytes[1]);
                        }
                        break;
                    }
                }
                if (block)
                    dwarf_dealloc(dbg, block, DW_DLA_BLOCK);
            }
        }
    }

    return loc;
}

// Get type information
std::string GetTypeInfo(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Error *error)
{
    Dwarf_Attribute type_attr = 0;
    if (dwarf_attr(die, DW_AT_type, &type_attr, error) == DW_DLV_OK)
    {
        Dwarf_Off type_offset = 0;
        if (dwarf_global_formref(type_attr, &type_offset, error) == DW_DLV_OK)
        {
            auto it = g_typeMap.find(type_offset);
            if (it != g_typeMap.end())
            {
                dwarf_dealloc_attribute(type_attr);
                return it->second.name;
            }

            Dwarf_Die type_die = 0;

            if (dwarf_offdie_b(dbg, type_offset, TRUE, &type_die, error) == DW_DLV_OK)
            {
                char *type_name = 0;
                std::string result = "unknown";

                if (dwarf_diename(type_die, &type_name, error) == DW_DLV_OK && type_name)
                {
                    result = type_name;
                    dwarf_dealloc(dbg, type_name, DW_DLA_STRING);
                }
                else
                {
                    Dwarf_Half tag = 0;
                    if (dwarf_tag(type_die, &tag, error) == DW_DLV_OK)
                    {
                        switch (tag)
                        {
                        case DW_TAG_base_type:
                            result = "base_type";
                            break;
                        case DW_TAG_pointer_type:
                            result = "pointer";
                            break;
                        case DW_TAG_array_type:
                            result = "array";
                            break;
                        case DW_TAG_structure_type:
                            result = "struct";
                            break;
                        case DW_TAG_union_type:
                            result = "union";
                            break;
                        case DW_TAG_enumeration_type:
                            result = "enum";
                            break;
                        case DW_TAG_typedef:
                            result = "typedef";
                            break;
                        case DW_TAG_const_type:
                            result = "const";
                            break;
                        case DW_TAG_volatile_type:
                            result = "volatile";
                            break;
                        case DW_TAG_subroutine_type:
                            result = "function";
                            break;
                        }
                    }
                }

                TypeInfo typeInfo = {result, 0, "", 0, {}};
                g_typeMap[type_offset] = typeInfo;

                dwarf_dealloc_die(type_die);
                dwarf_dealloc_attribute(type_attr);
                return result;
            }
        }
        dwarf_dealloc_attribute(type_attr);
    }
    return "";
}

// Get compilation directory
std::string GetCompilationDirectory(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Error *error)
{
    Dwarf_Attribute comp_dir_attr = 0;
    std::string comp_dir;

    if (dwarf_attr(cu_die, DW_AT_comp_dir, &comp_dir_attr, error) == DW_DLV_OK)
    {
        char *dir_name = 0;
        if (dwarf_formstring(comp_dir_attr, &dir_name, error) == DW_DLV_OK && dir_name)
        {
            comp_dir = dir_name;
            dwarf_dealloc(dbg, dir_name, DW_DLA_STRING);
        }
        dwarf_dealloc_attribute(comp_dir_attr);
    }

    return comp_dir;
}

// Process additional attributes
void ProcessAdditionalAttributes(Dwarf_Debug dbg, Dwarf_Die die, Symbol &symbol,
                                 const std::string &comp_dir, Dwarf_Error *error)
{
    symbol.compDir = comp_dir;

    symbol.type = GetTypeInfo(dbg, die, error);

    Dwarf_Attribute line_attr = 0;
    if (dwarf_attr(die, DW_AT_decl_line, &line_attr, error) == DW_DLV_OK)
    {
        Dwarf_Unsigned line_no = 0;
        if (dwarf_formudata(line_attr, &line_no, error) == DW_DLV_OK)
        {
            symbol.line = static_cast<int>(line_no);
        }
        dwarf_dealloc_attribute(line_attr);
    }

    Dwarf_Attribute linkage_attr = 0;
    if (dwarf_attr(die, DW_AT_linkage_name, &linkage_attr, error) == DW_DLV_OK ||
        dwarf_attr(die, DW_AT_MIPS_linkage_name, &linkage_attr, error) == DW_DLV_OK)
    {
        char *linkage_name = 0;
        if (dwarf_formstring(linkage_attr, &linkage_name, error) == DW_DLV_OK && linkage_name)
        {
            symbol.linkageName = linkage_name;
            dwarf_dealloc(dbg, linkage_name, DW_DLA_STRING);
        }
        dwarf_dealloc_attribute(linkage_attr);
    }

    Dwarf_Attribute external_attr = 0;
    if (dwarf_attr(die, DW_AT_external, &external_attr, error) == DW_DLV_OK)
    {
        Dwarf_Bool is_external = 0;
        if (dwarf_formflag(external_attr, &is_external, error) == DW_DLV_OK)
        {
            symbol.isExternal = (is_external != 0);
        }
        dwarf_dealloc_attribute(external_attr);
    }

    Dwarf_Attribute location_attr = 0;
    if (dwarf_attr(die, DW_AT_location, &location_attr, error) == DW_DLV_OK)
    {
        symbol.location = ProcessLocationExpression(dbg, location_attr, error);
        dwarf_dealloc_attribute(location_attr);
    }
}

// Parse DWARF line information from file
static std::vector<LineInfo> ParseDWARFLineInfo(Dwarf_Debug dbg, duint dwarfImageBase, duint runtimeBase, duint modSize)
{
    DPUTS("Entering ParseDWARFLineInfo");
    std::vector<LineInfo> lineInfos;

    if (!dbg)
    {
        DPUTS("Invalid Dwarf_Debug context in ParseDWARFLineInfo");
        return lineInfos;
    }

    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half offset_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 signature;
    Dwarf_Unsigned typeoffset = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Half header_cu_type = 0;
    Dwarf_Bool is_info = TRUE;
    Dwarf_Error error = 0;

    while (dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version, &abbrev_offset,
                                  &address_size, &offset_size, &extension_size, &signature,
                                  &typeoffset, &next_cu_header, &header_cu_type, &error) == DW_DLV_OK)
    {
        Dwarf_Die cu_die = 0;
        if (dwarf_siblingof_b(dbg, 0, is_info, &cu_die, &error) != DW_DLV_OK)
        {
            DPUTS("Failed to get CU DIE for line info");
            dwarf_dealloc_error(dbg, error);
            continue;
        }

        Dwarf_Unsigned line_version = 0;
        Dwarf_Small table_type = 0;
        Dwarf_Line_Context line_context = 0;
        if (dwarf_srclines_b(cu_die, &line_version, &table_type, &line_context, &error) == DW_DLV_OK)
        {
            Dwarf_Line *linebuf = 0;
            Dwarf_Signed linecount = 0;
            if (dwarf_srclines_from_linecontext(line_context, &linebuf, &linecount, &error) == DW_DLV_OK)
            {
                for (Dwarf_Signed i = 0; i < linecount; ++i)
                {
                    Dwarf_Addr lineaddr = 0;
                    char *filename = 0;
                    Dwarf_Unsigned lineno = 0;
                    if (dwarf_lineaddr(linebuf[i], &lineaddr, &error) == DW_DLV_OK &&
                        dwarf_linesrc(linebuf[i], &filename, &error) == DW_DLV_OK &&
                        dwarf_lineno(linebuf[i], &lineno, &error) == DW_DLV_OK)
                    {
                        if (lineaddr != 0 && filename && lineno != 0)
                        {
                            duint adjusted_addr;
                            if (dwarfImageBase != 0)
                            {
                                adjusted_addr = (static_cast<duint>(lineaddr) - dwarfImageBase) + runtimeBase;
                            }
                            else
                            {
                                adjusted_addr = static_cast<duint>(lineaddr) + runtimeBase;
                            }

                            if (modSize == 0 || IsValidModuleAddress(adjusted_addr, runtimeBase, modSize))
                            {
                                lineInfos.push_back({std::string(filename), static_cast<unsigned int>(lineno), adjusted_addr});
                                DPRINTF("Line info: %s:%u at DWARF addr 0x%llX -> runtime addr 0x%llX",
                                        filename, lineno, lineaddr, adjusted_addr);
                            }
                            else
                            {
                                DPRINTF("Skipped line info: %s:%u, invalid address 0x%llX", filename, lineno, adjusted_addr);
                            }
                        }
                        if (filename)
                        {
                            dwarf_dealloc(dbg, filename, DW_DLA_STRING);
                        }
                    }
                }
                dwarf_srclines_dealloc_b(line_context);
            }
        }
        dwarf_dealloc_die(cu_die);
    }
    DPRINTF("ParseDWARFLineInfo: Loaded %zu line entries", lineInfos.size());
    return lineInfos;
}

// Process DIE and its children
void ProcessDIE(Dwarf_Debug dbg, Dwarf_Die die, std::vector<Symbol> &loadedSymbols,
                duint runtimeBase, duint modSize, Dwarf_Bool is_info,
                const std::string &currentFile = "", const std::string &comp_dir = "")
{
    Dwarf_Error error = 0;

    Dwarf_Half tag = 0;
    if (dwarf_tag(die, &tag, &error) != DW_DLV_OK)
    {
        if (error)
            dwarf_dealloc_error(dbg, error);
        return;
    }

    if (tag == DW_TAG_subprogram || tag == DW_TAG_variable ||
        tag == DW_TAG_label || tag == DW_TAG_formal_parameter ||
        tag == DW_TAG_enumerator || tag == DW_TAG_constant ||
        tag == DW_TAG_member || tag == DW_TAG_inlined_subroutine ||
        tag == DW_TAG_namespace || tag == DW_TAG_class_type ||
        tag == DW_TAG_structure_type || tag == DW_TAG_union_type ||
        tag == DW_TAG_enumeration_type || tag == DW_TAG_typedef)
    {
        char *name = 0;
        if (dwarf_diename(die, &name, &error) == DW_DLV_OK && name && strlen(name) > 0)
        {
            std::string symbolName = name;
            dwarf_dealloc(dbg, name, DW_DLA_STRING);

            if (symbolName.find("__") == 0 || symbolName.empty())
            {
                return;
            }

            Dwarf_Addr low_pc = 0;
            Dwarf_Attribute attr = 0;

            if (dwarf_attr(die, DW_AT_low_pc, &attr, &error) == DW_DLV_OK)
            {
                if (dwarf_formaddr(attr, &low_pc, &error) == DW_DLV_OK && low_pc != 0)
                {
                    duint adjusted_addr = g_addressCache.TranslateAddress(static_cast<duint>(low_pc));

                    if (modSize > 0 && !IsValidModuleAddress(adjusted_addr, runtimeBase, modSize))
                    {
                        DPRINTF("Skipped symbol %s: address 0x%llX outside module range",
                                symbolName.c_str(), adjusted_addr);
                        dwarf_dealloc_attribute(attr);
                        return;
                    }

                    std::string cleaned_name = CleanSymbolName(symbolName);
                    duint symbolSize = 0;
                    duint endAddress = adjusted_addr;

                    if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine)
                    {
                        symbolSize = GetFunctionSize(die, dbg, low_pc, &error);
                        endAddress = adjusted_addr + symbolSize;

                        if (modSize > 0 && endAddress > runtimeBase + modSize)
                        {
                            endAddress = runtimeBase + modSize;
                            symbolSize = endAddress - adjusted_addr;
                        }
                    }

                    Symbol symbol = {cleaned_name, adjusted_addr, tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine, symbolSize, endAddress, currentFile, "", {LocationInfo::INVALID, 0, 0, 0, {}}, "", 0, false, ""};

                    ProcessAdditionalAttributes(dbg, die, symbol, comp_dir, &error);

                    loadedSymbols.push_back(symbol);

                    DPRINTF("Added %s symbol: %s at 0x%llX (size: %llu, type: %s)",
                            symbol.isFunction ? "function" : "symbol",
                            cleaned_name.c_str(), adjusted_addr, symbolSize, symbol.type.c_str());
                }
                dwarf_dealloc_attribute(attr);
            }
            else if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter ||
                     tag == DW_TAG_constant || tag == DW_TAG_member)
            {
                Symbol symbol = {CleanSymbolName(symbolName), 0, false, 0, 0, currentFile, "", {LocationInfo::INVALID, 0, 0, 0, {}}, "", 0, false, ""};

                ProcessAdditionalAttributes(dbg, die, symbol, comp_dir, &error);

                if (symbol.location.type != LocationInfo::INVALID)
                {
                    loadedSymbols.push_back(symbol);
                    DPRINTF("Added variable symbol: %s (type: %s)",
                            symbol.name.c_str(), symbol.type.c_str());
                }
            }
        }
    }

    Dwarf_Die child_die = 0;
    if (dwarf_child(die, &child_die, &error) == DW_DLV_OK)
    {
        ProcessDIE(dbg, child_die, loadedSymbols, runtimeBase, modSize, is_info, currentFile, comp_dir);

        Dwarf_Die sibling_die = 0;
        while (dwarf_siblingof_b(dbg, child_die, is_info, &sibling_die, &error) == DW_DLV_OK)
        {
            dwarf_dealloc_die(child_die);
            child_die = sibling_die;
            ProcessDIE(dbg, child_die, loadedSymbols, runtimeBase, modSize, is_info, currentFile, comp_dir);
        }
        dwarf_dealloc_die(child_die);
    }
}

// Parse DWARF symbols from file
std::vector<Symbol> ParseDWARFFile(const std::filesystem::path &path, duint runtimeBase)
{
    DPUTS("Entering ParseDWARFFile");
    std::vector<Symbol> loadedSymbols;

    try
    {
        MODULEINFO modInfo = {0};
        duint modSize = 0;
        if (runtimeBase)
        {
            HANDLE hProcess = GetCurrentProcess();
            HMODULE hModule = (HMODULE)runtimeBase;
            if (GetModuleInformation(hProcess, hModule, &modInfo, sizeof(MODULEINFO)))
            {
                modSize = modInfo.SizeOfImage;
                DPRINTF("Module info: base=0x%llX, size=0x%llX", runtimeBase, modSize);
            }
        }

        Dwarf_Debug dbg = 0;
        Dwarf_Error error = 0;

        int res = dwarf_init_path_a(path.string().c_str(), NULL, 0, DW_GROUPNUMBER_ANY, 0,
                                    NULL, NULL, &dbg, &error);
        if (res != DW_DLV_OK)
        {
            DPRINTF("dwarf_init_path_a failed: %d", res);
            if (error)
            {
                DPRINTF("Error: %s", dwarf_errmsg(error));
                dwarf_dealloc_error(dbg, error);
            }
            return loadedSymbols;
        }

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            dwarf_finish(dbg);
            return loadedSymbols;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0);

        std::vector<char> fileData(fileSize);
        file.read(fileData.data(), fileSize);
        file.close();

        duint dwarfImageBase = GetImageBaseFromHeaders(fileData.data(), fileSize);
        g_addressCache.Initialize(dwarfImageBase, runtimeBase);

        Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header, typeoffset;
        Dwarf_Half version, address_size, offset_size, extension_size, header_cu_type;
        Dwarf_Sig8 signature;
        Dwarf_Bool is_info = TRUE;

        while (dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version, &abbrev_offset,
                                      &address_size, &offset_size, &extension_size, &signature,
                                      &typeoffset, &next_cu_header, &header_cu_type, &error) == DW_DLV_OK)
        {
            Dwarf_Die cu_die = 0;
            if (dwarf_siblingof_b(dbg, 0, is_info, &cu_die, &error) == DW_DLV_OK)
            {
                char *cu_name = 0;
                std::string currentFile;
                std::string comp_dir = GetCompilationDirectory(dbg, cu_die, &error);

                if (dwarf_diename(cu_die, &cu_name, &error) == DW_DLV_OK && cu_name)
                {
                    currentFile = cu_name;
                    dwarf_dealloc(dbg, cu_name, DW_DLA_STRING);
                }

                if (!comp_dir.empty() && !currentFile.empty())
                {
                    g_compDirMap[currentFile] = comp_dir;
                }

                DPRINTF("Processing CU: %s (comp_dir: %s, version: %d)",
                        currentFile.c_str(), comp_dir.c_str(), version);

                ProcessDIE(dbg, cu_die, loadedSymbols, runtimeBase, modSize, is_info, currentFile, comp_dir);
                dwarf_dealloc_die(cu_die);
            }
        }

        auto lineInfos = ParseDWARFLineInfo(dbg, dwarfImageBase, runtimeBase, modSize);
        DPRINTF("Processed %zu line info entries", lineInfos.size());
        

        dwarf_finish(dbg);

        ParseCOFFSymbols(path, runtimeBase, dwarfImageBase, modSize, loadedSymbols);
        
        DPRINTF("ParseDWARFFile completed: %zu symbols loaded", loadedSymbols.size());
        return loadedSymbols;
    }
    catch (const std::exception &ex)
    {
        DPRINTF("Exception in ParseDWARFFile: %s", ex.what());
        return loadedSymbols;
    }
    catch (...)
    {
        DPUTS("Unknown exception in ParseDWARFFile");
        return loadedSymbols;
    }
}

// Load symbols into x64dbg
void LoadSymbols(duint runtimeBase, const std::vector<Symbol> &loadedSymbols)
{
    DPUTS("Entering LoadSymbols");
    DPRINTF("Runtime base: 0x%llX, Symbols count: %zu", runtimeBase, loadedSymbols.size());

    if (loadedSymbols.empty())
    {
        MessageBoxA(NULL, "No symbols to load.", "DWARFHelper", MB_OK | MB_ICONWARNING);
        return;
    }

    int labelCount = 0;
    int functionCount = 0;
    int commentCount = 0;
    int typeCount = 0;

    for (const auto &sym : loadedSymbols)
    {
        if (sym.address == 0 && sym.location.type == LocationInfo::INVALID)
        {
            continue;
        }

        if (sym.address != 0)
        {
            char existingLabel[MAX_LABEL_SIZE] = "";
            if (DbgGetLabelAt(sym.address, SEG_DEFAULT, existingLabel) && strlen(existingLabel) > 0)
            {
                DPRINTF("Skipping label %s at 0x%llX, already exists: %s",
                        sym.name.c_str(), sym.address, existingLabel);
                continue;
            }

            if (DbgSetLabelAt(sym.address, sym.name.c_str()))
            {
                labelCount++;
                DPRINTF("Set label: %s at 0x%llX", sym.name.c_str(), sym.address);
            }
        }

        if (sym.address != 0 && DbgSetLabelAt(sym.address, sym.name.c_str()))
        {
            labelCount++;
            DPRINTF("Set label: %s at 0x%llX", sym.name.c_str(), sym.address);
        }

        if (!sym.fileName.empty() || !sym.type.empty() || sym.location.type != LocationInfo::INVALID)
        {
            std::string filename = sym.fileName;
            size_t lastSlash = filename.find_last_of("/\\");
            if (lastSlash != std::string::npos)
            {
                filename = filename.substr(lastSlash + 1);
            }

            char comment[1024] = "";
            std::string locationStr;

            switch (sym.location.type)
            {
            case LocationInfo::ADDRESS:
                snprintf(comment + strlen(comment), sizeof(comment) - strlen(comment),
                         " @0x%llX", sym.location.address);
                break;
            case LocationInfo::REGISTER:
                snprintf(comment + strlen(comment), sizeof(comment) - strlen(comment),
                         " reg%d", sym.location.reg);
                break;
            case LocationInfo::STACK_OFFSET:
                snprintf(comment + strlen(comment), sizeof(comment) - strlen(comment),
                         " [%+d]", sym.location.offset);
                break;
            }

            if (sym.isFunction)
            {
                std::string lineStr = (sym.line > 0) ? (":" + std::to_string(sym.line)) : "";

                snprintf(comment, sizeof(comment),
                         "Function: %s%s%s (size: %llu)%s%s - %s%s",
                         sym.name.c_str(),
                         sym.type.empty() ? "" : " -> ",
                         sym.type.c_str(),
                         sym.size,
                         sym.linkageName.empty() ? "" : " [",
                         sym.linkageName.c_str(),
                         sym.linkageName.empty() ? "" : "]",
                         filename.c_str(),
                         lineStr.c_str());
            }
            else
            {
                std::string symStr = (sym.line > 0) ? (":" + std::to_string(sym.line)) : "";

                snprintf(comment, sizeof(comment),
                         "Symbol: %s%s%s%s - %s%s",
                         sym.name.c_str(),
                         sym.type.empty() ? "" : " (",
                         sym.type.c_str(),
                         sym.type.empty() ? "" : ")",
                         locationStr.c_str(),
                         filename.c_str(),
                         symStr.c_str());
            }

            if (sym.address != 0 && DbgSetCommentAt(sym.address, comment))
            {
                commentCount++;
            }
        }

        if (!sym.type.empty())
        {
            typeCount++;
        }
    }

    for (const auto &sym : loadedSymbols)
    {
        if (sym.isFunction && sym.size > 0 && sym.address != 0)
        {
            duint startAddr = sym.address;
            duint endAddr = sym.endAddress;

            MEMORY_BASIC_INFORMATION mbi = {0};
            if (VirtualQuery((LPCVOID)startAddr, &mbi, sizeof(mbi)))
            {
                bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                bool isCommitted = (mbi.State == MEM_COMMIT);

                if (isCommitted && isExecutable)
                {
                    DbgFunctionDel(startAddr);

                    if (DbgFunctionAdd(startAddr, endAddr))
                    {
                        functionCount++;
                        DPRINTF("Created function: %s at 0x%llX-0x%llX",
                                sym.name.c_str(), startAddr, endAddr);
                    }
                }
            }
        }
    }

    GuiUpdateAllViews();

    char msg[1024];
    snprintf(msg, sizeof(msg),
             "DWARF Symbols Loaded Successfully!\n\n"
             "Labels set: %d/%zu\n"
             "Functions created: %d\n"
             "Comments added: %d\n"
             "Types processed: %d\n"
             "Compilation units: %zu\n\n"
             "Features:\n"
             "• Enhanced type information\n"
             "• Location expressions (DW_OP_*)\n"
             "• Compilation directories\n"
             "• DWARF 5 compatibility",
             labelCount, loadedSymbols.size(), functionCount, commentCount,
             typeCount, g_compDirMap.size());

    MessageBoxA(NULL, msg, "DWARFHelper", MB_OK | MB_ICONINFORMATION);

    DPRINTF("LoadSymbols completed: %d labels, %d functions, %d comments, %d types",
            labelCount, functionCount, commentCount, typeCount);
}

// Helper function to select file using IFileOpenDialog and load symbols
bool LoadSymbolsFromFile()
{
    DPUTS("Entering LoadSymbolsFromFile");

    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr))
    {
        DPRINTF("CoInitialize failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to initialize COM.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    IFileOpenDialog *pFileOpen = NULL;
    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileOpen));
    if (FAILED(hr))
    {
        DPRINTF("CoCreateInstance failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to create file open dialog.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        CoUninitialize();
        return false;
    }

    COMDLG_FILTERSPEC fileTypes[] = {
        {L"Executable Files (*.exe;*.dll;*.elf)", L"*.exe;*.dll;*.elf"},
        {L"All Files (*.*)", L"*.*"}};
    hr = pFileOpen->SetFileTypes(2, fileTypes);
    if (FAILED(hr))
    {
        DPRINTF("SetFileTypes failed, HRESULT=0x%X", hr);
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    hr = pFileOpen->SetDefaultExtension(L"exe");
    if (FAILED(hr))
    {
        DPRINTF("SetDefaultExtension failed, HRESULT=0x%X", hr);
    }

    duint runtimeBase = 0;
    char moduleName[MAX_PATH] = "";
    duint currentEIP = GetCurrentEIP();
    auto *dbgFuncs = DbgFunctions();
    DPRINTF("DbgFunctions() returned 0x%p", dbgFuncs);
    if (!dbgFuncs)
    {
        DPUTS("DbgFunctions() returned nullptr");
        pFileOpen->Release();
        CoUninitialize();
        MessageBoxA(NULL, "Failed to get DbgFunctions. SDK may be incompatible.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    if (currentEIP)
    {
        if (DbgGetModuleAt(currentEIP, moduleName))
        {
            DPRINTF("DbgGetModuleAt succeeded, module name: %s", moduleName);
            runtimeBase = dbgFuncs->ModBaseFromName(moduleName);
            DPRINTF("DbgFunctions()->ModBaseFromName returned 0x%llX", runtimeBase);
        }
        else
        {
            DPUTS("DbgGetModuleAt failed");
        }
    }
    else
    {
        DPUTS("Warning: cip is 0, invalid instruction pointer");
    }

    if (!runtimeBase)
    {
        DPUTS("No process to add DWARF info");
        MessageBoxA(NULL, "No process is being debugged. Please start debugging a process first.", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    char modulePath[MAX_PATH] = "";
    char initialDir[MAX_PATH] = "";
    if (dbgFuncs->ModPathFromAddr(runtimeBase, modulePath, MAX_PATH))
    {
        DPRINTF("Module path: %s", modulePath);
        strncpy_s(initialDir, modulePath, MAX_PATH);
        char *lastSlash = strrchr(initialDir, '\\');
        if (lastSlash)
            *lastSlash = '\0';
        DPRINTF("Initial directory: %s", initialDir);
        std::wstring wInitialDir = std::wstring(initialDir, initialDir + strlen(initialDir));
        IShellItem *pFolder = NULL;
        if (SUCCEEDED(SHCreateItemFromParsingName(wInitialDir.c_str(), NULL, IID_PPV_ARGS(&pFolder))))
        {
            pFileOpen->SetFolder(pFolder);
            pFolder->Release();
        }
    }

    HWND hwnd = GuiGetWindowHandle();
    DPRINTF("Opening file dialog, GuiGetWindowHandle=0x%p, IsWindow(GuiGetWindowHandle)=%d", hwnd, IsWindow(hwnd));
    hr = pFileOpen->Show(hwnd && IsWindow(hwnd) ? hwnd : NULL);
    if (FAILED(hr))
    {
        DPRINTF("IFileOpenDialog::Show failed, HRESULT=0x%X", hr);
        DPUTS("No file selected");
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    IShellItem *pItem = NULL;
    hr = pFileOpen->GetResult(&pItem);
    if (SUCCEEDED(hr))
    {
        PWSTR pszFilePath = NULL;
        hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
        if (SUCCEEDED(hr))
        {
            char filePath[MAX_PATH] = "";
            WideCharToMultiByte(CP_ACP, 0, pszFilePath, -1, filePath, MAX_PATH, NULL, NULL);
            DPRINTF("Selected file: %s", filePath);
            CoTaskMemFree(pszFilePath);

            auto loadedSymbols = ParseDWARFFile(filePath, runtimeBase);
            if (!loadedSymbols.empty())
            {
                DPRINTF("Loaded %zu symbols", loadedSymbols.size());
                LoadSymbols(runtimeBase, loadedSymbols);
            }
            else
            {
                DPUTS("Failed to parse DWARF debug info");
            }
        }
        else
        {
            DPRINTF("GetDisplayName failed, HRESULT=0x%X", hr);
        }
        pItem->Release();
    }
    else
    {
        DPRINTF("GetResult failed, HRESULT=0x%X", hr);
        DPUTS("No file selected");
    }

    pFileOpen->Release();
    CoUninitialize();
    return true;
}

// Menu callback
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY *info)
{
    DPRINTF("CBMENUENTRY called with cbType=%d, hEntry=%d", cbType, info ? info->hEntry : -1);
    if (cbType != CB_MENUENTRY || !info)
    {
        DPUTS("Invalid cbType or menu entry info");
        return;
    }

    switch (info->hEntry)
    {
    case MA_LABELS_DWARF:
        DPUTS("Selected: Load DWARF Symbols from File");
        if (!DbgIsDebugging())
        {
            DPUTS("No process is being debugged");
            MessageBoxA(NULL, "No process is being debugged. Please start debugging a process first.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            return;
        }
        LoadSymbolsFromFile();
        break;
    case MA_ABOUT:
        DPRINTF("Showing About dialog, hwndDlg=0x%p", hwndDlg);
        MessageBoxA(NULL, "DWARFHelper Plugin v1.1 \nLoad DWARF symbols as labels\n By CynicRus", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        break;

    default:
        DPRINTF("Unknown menu entry: %d", info->hEntry);
        break;
    }
    GuiUpdateDisassemblyView();
}

// Plugin initialization
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct)
{
    DPUTS("pluginit called");
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, sizeof(initStruct->pluginName));
    pluginHandle = initStruct->pluginHandle;
    DPRINTF("Plugin initialized: handle=%d, version=%d, sdkVersion=%d", pluginHandle, PLUGIN_VERSION, PLUG_SDKVERSION);
    return true;
}

// Plugin setup
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    menuHandleLabelsDWARF = _plugin_menuaddentry(setupStruct->hMenu, MA_LABELS_DWARF, "Load DWARF Symbols from File");
    menuHandleAbout = _plugin_menuaddentry(setupStruct->hMenu, MA_ABOUT, "About");
}

// Plugin cleanup
PLUG_EXPORT bool plugstop()
{
    _plugin_menuclear(pluginHandle);
    return true;
}

// DLL entry point
BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE hinstDLL, [[maybe_unused]] DWORD fdwReason, [[maybe_unused]] LPVOID lpvReserved)
{
    return TRUE;
}
