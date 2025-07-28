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
#include <memory>
#include <optional>
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
#endif

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

// Menu entry IDs
enum MenuAction
{
    MA_LABELS_DWARF = 1001,
    MA_ABOUT = 1004
};

// Structure definitions
struct TypeInfo
{
    std::string name;
    duint size;
    std::string encoding;
    duint baseTypeOffset;
    std::vector<std::string> members;
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
    std::vector<uint8_t> expression;
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
    std::string compDir;
    int line;
    bool isExternal;
    std::string linkageName;
};

struct LineInfo
{
    std::string file;
    unsigned int line;
    duint address;
};

// RAII wrapper for automatic DWARF attribute cleanup
class DwarfAttributeGuard {
public:
    explicit DwarfAttributeGuard(Dwarf_Attribute attr) : attr_(attr) {}
    ~DwarfAttributeGuard() {
        if (attr_) {
            dwarf_dealloc_attribute(attr_);
        }
    }
    
    DwarfAttributeGuard(const DwarfAttributeGuard&) = delete;
    DwarfAttributeGuard& operator=(const DwarfAttributeGuard&) = delete;
    
private:
    Dwarf_Attribute attr_;
};

// Check if DIE tag represents a symbol we want to process
[[nodiscard]] inline bool IsSymbolTag(Dwarf_Half tag) noexcept {
    // Hot path optimization: most common tags first
    switch (tag) {
        case DW_TAG_subprogram:
        case DW_TAG_variable:
        case DW_TAG_inlined_subroutine:
        case DW_TAG_formal_parameter:
            return true;
        case DW_TAG_label:
        case DW_TAG_enumerator:
        case DW_TAG_constant:
        case DW_TAG_member:
        case DW_TAG_namespace:
        case DW_TAG_class_type:
        case DW_TAG_structure_type:
        case DW_TAG_union_type:
        case DW_TAG_enumeration_type:
        case DW_TAG_typedef:
            return true;
        default:
            return false;
    }
}

// Check if DIE tag represents a function-like symbol
[[nodiscard]] inline bool IsFunctionTag(Dwarf_Half tag) noexcept {
    return tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine;
}

// Validate symbol name quality
[[nodiscard]] bool IsValidSymbolName(const char* name) noexcept {
    if (!name) return false;
    
    const size_t len = strlen(name);
    if (len == 0 || len > 2048) return false; // Reasonable length limits
    
    // Filter out compiler-generated garbage
    if (len >= 3 && name[0] == '_' && name[1] == '_' && name[2] == '_') return false;
    if (strstr(name, "..") != nullptr) return false; // Likely corrupted
    if (strstr(name, "\x00") != nullptr) return false; // Embedded nulls
    
    // Check for reasonable character content
    size_t printable_count = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(name[i]);
        if (c >= 32 && c <= 126) { // Printable ASCII
            ++printable_count;
        } else if (c < 32 && c != '\t') { // Control chars except tab
            return false;
        }
    }
    
    // At least 80% should be printable
    return (printable_count * 5) >= (len * 4);
}

// Validate function size for reasonableness
[[nodiscard]] bool IsValidFunctionSize(duint size) noexcept {
    return size > 0 && size <= 0x10000000; // Max 256MB - reasonable function limit
}

// Manages address translation between DWARF and runtime addresses
class AddressTranslator {
public:
    // Initialize with DWARF and runtime base addresses
    void Initialize(duint dwarf_base, duint runtime_base) {
        imageBase = dwarf_base;
        runtimeBase = runtime_base;
        baseOffset = runtime_base - dwarf_base;
        dwarfToRuntime.clear();
        DPRINTF("Address cache initialized: DWARF base=0x%llX, Runtime base=0x%llX, Offset=0x%llX",
                dwarf_base, runtime_base, baseOffset);
    }

    // Translate DWARF address to runtime address, caching results
    duint TranslateAddress(duint dwarf_addr) {
        if (imageBase == 0 && runtimeBase == 0) return dwarf_addr;

        auto it = dwarfToRuntime.find(dwarf_addr);
        if (it != dwarfToRuntime.end()) return it->second;

        duint runtime_addr = (dwarf_addr >= imageBase) ? 
            (dwarf_addr - imageBase) + runtimeBase : 
            dwarf_addr + runtimeBase;

        dwarfToRuntime[dwarf_addr] = runtime_addr;
        DPRINTF("Translated address: 0x%llX -> 0x%llX (imageBase=0x%llX, runtimeBase=0x%llX)",
                dwarf_addr, runtime_addr, imageBase, runtimeBase);
        return runtime_addr;
    }

private:
    std::unordered_map<duint, duint> dwarfToRuntime;
    duint imageBase = 0;
    duint runtimeBase = 0;
    duint baseOffset = 0;
};

// Handles file operations and utility functions
class FileHandler {
public:
    // Opens a file dialog to select an executable file
    static std::optional<std::filesystem::path> OpenFileDialog(duint runtimeBase) {
        DPUTS("Entering OpenFileDialog");
        HRESULT hr = CoInitialize(NULL);
        if (FAILED(hr)) {
            DPRINTF("CoInitialize failed, HRESULT=0x%X", hr);
            MessageBoxA(NULL, "Failed to initialize COM.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            return std::nullopt;
        }

        IFileOpenDialog* pFileOpen = nullptr;
        hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileOpen));
        if (FAILED(hr)) {
            DPRINTF("CoCreateInstance failed, HRESULT=0x%X", hr);
            MessageBoxA(NULL, "Failed to create file open dialog.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            CoUninitialize();
            return std::nullopt;
        }

        COMDLG_FILTERSPEC fileTypes[] = {
            {L"Executable Files (*.exe;*.dll;*.elf)", L"*.exe;*.dll;*.elf"},
            {L"All Files (*.*)", L"*.*"}
        };
        pFileOpen->SetFileTypes(2, fileTypes);
        pFileOpen->SetDefaultExtension(L"exe");

        char modulePath[MAX_PATH] = "";
        char initialDir[MAX_PATH] = "";
        if (DbgFunctions()->ModPathFromAddr(runtimeBase, modulePath, MAX_PATH)) {
            strncpy_s(initialDir, modulePath, MAX_PATH);
            char* lastSlash = strrchr(initialDir, '\\');
            if (lastSlash) *lastSlash = '\0';
            std::wstring wInitialDir = std::wstring(initialDir, initialDir + strlen(initialDir));
            IShellItem* pFolder = NULL;
            if (SUCCEEDED(SHCreateItemFromParsingName(wInitialDir.c_str(), NULL, IID_PPV_ARGS(&pFolder)))) {
                pFileOpen->SetFolder(pFolder);
                pFolder->Release();
            }
        }

        HWND hwnd = GuiGetWindowHandle();
        hr = pFileOpen->Show(hwnd && IsWindow(hwnd) ? hwnd : NULL);
        if (FAILED(hr)) {
            pFileOpen->Release();
            CoUninitialize();
            return std::nullopt;
        }

        IShellItem* pItem = NULL;
        hr = pFileOpen->GetResult(&pItem);
        if (SUCCEEDED(hr)) {
            PWSTR pszFilePath = NULL;
            hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
            if (SUCCEEDED(hr)) {
                char filePath[MAX_PATH] = "";
                WideCharToMultiByte(CP_ACP, 0, pszFilePath, -1, filePath, MAX_PATH, NULL, NULL);
                DPRINTF("Selected file: %s", filePath);
                CoTaskMemFree(pszFilePath);
                pItem->Release();
                pFileOpen->Release();
                CoUninitialize();
                return std::filesystem::path(filePath);
            }
            pItem->Release();
        }
        pFileOpen->Release();
        CoUninitialize();
        return std::nullopt;
    }

    // Extracts image base from PE headers
    static duint GetImageBaseFromHeaders(const void* imageData, size_t imageSize) {
        if (!imageData || imageSize < sizeof(IMAGE_DOS_HEADER)) return 0;

        const IMAGE_DOS_HEADER* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(imageData);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            DPUTS("Invalid DOS signature");
            return 0;
        }

        if (static_cast<size_t>(dosHeader->e_lfanew) >= imageSize || dosHeader->e_lfanew < 0) {
            DPUTS("Invalid PE header offset");
            return 0;
        }

        const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const char*>(imageData) + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            DPUTS("Invalid NT signature");
            return 0;
        }

        duint imageBase = static_cast<duint>(ntHeaders->OptionalHeader.ImageBase);
        DPRINTF("Image base from headers: 0x%llX", imageBase);
        return imageBase;
    }

    // Gets the base address of the current module
    static duint GetModuleBase() {
        REGDUMP registers;
        duint currentEIP = DbgIsDebugging() && DbgGetRegDumpEx(&registers, sizeof(REGDUMP)) ? 
                           registers.regcontext.cip : 0;
        if (!currentEIP) return 0;

        char moduleName[MAX_PATH] = "";
        if (!DbgGetModuleAt(currentEIP, moduleName)) return 0;

        auto* dbgFuncs = DbgFunctions();
        return dbgFuncs ? dbgFuncs->ModBaseFromName(moduleName) : 0;
    }

    // Gets the size of the module
    static duint GetModuleSize(duint moduleBase) {
        if (!moduleBase) return 0;

        MODULEINFO modInfo = {0};
        if (GetModuleInformation(GetCurrentProcess(), (HMODULE)moduleBase, &modInfo, sizeof(MODULEINFO)))
            return modInfo.SizeOfImage;
        return 0;
    }

    // Cleans symbol names for x64dbg compatibility
    static std::string CleanSymbolName(const std::string& name) {
        std::string cleaned = name;
        for (char& c : cleaned) {
            if (c == '$' || c == ':' || c == '@' || (!std::isalnum(c) && c != '_')) {
                c = '_';
            }
        }
        while (!cleaned.empty() && cleaned.front() == '_') cleaned.erase(cleaned.begin());
        while (!cleaned.empty() && cleaned.back() == '_') cleaned.pop_back();
        return cleaned.empty() ? "Symbol" : cleaned;
    }

    // Validates if an address is within module bounds
    static bool IsValidModuleAddress(duint address, duint modBase, duint modSize) {
        return address >= modBase && address < modBase + modSize;
    }
};

// Parses DWARF debug information from executable files
class DwarfParser {
public:
    DwarfParser(duint runtimeBase) : runtimeBase(runtimeBase) {
        modSize = FileHandler::GetModuleSize(runtimeBase);
    }

    ~DwarfParser() {
        if (dbg) dwarf_finish(dbg);
    }

    // Main entry point for parsing DWARF data
    bool ParseFile(const std::filesystem::path& path) {
        if (!OpenFile(path)) return false;
        ParseCompilationUnits();
        ParseLineInfo();
        ParseCOFFSymbols(path);
        return true;
    }

    // Accessors for parsed data
    const std::vector<Symbol>& GetSymbols() const { return loadedSymbols; }
    const std::vector<LineInfo>& GetLineInfo() const { return lineInfos; }

private:
    // Initializes DWARF debugging context
    bool OpenFile(const std::filesystem::path& path) {
        DPUTS("Entering OpenFile");
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            DPUTS("Failed to open file");
            return false;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0);
        fileData.resize(fileSize);
        file.read(fileData.data(), fileSize);
        file.close();

        Dwarf_Error error = 0;
        int res = dwarf_init_path_a(path.string().c_str(), NULL, 0, DW_GROUPNUMBER_ANY, 0, NULL, NULL, &dbg, &error);
        if (res != DW_DLV_OK) {
            DPRINTF("dwarf_init_path_a failed: %d", res);
            if (error) {
                DPRINTF("Error: %s", dwarf_errmsg(error));
                dwarf_dealloc_error(dbg, error);
            }
            return false;
        }

        dwarfImageBase = FileHandler::GetImageBaseFromHeaders(fileData.data(), fileSize);
        addressCache.Initialize(dwarfImageBase, runtimeBase);
        return true;
    }

    // Processes all compilation units
    void ParseCompilationUnits() {
        Dwarf_Error error = 0;
        Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header, typeoffset;
        Dwarf_Half version, address_size, offset_size, extension_size, header_cu_type;
        Dwarf_Sig8 signature;
        Dwarf_Bool is_info = TRUE;

        while (dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version, &abbrev_offset,
                                      &address_size, &offset_size, &extension_size, &signature,
                                      &typeoffset, &next_cu_header, &header_cu_type, &error) == DW_DLV_OK) {
            Dwarf_Die cu_die = 0;
            if (dwarf_siblingof_b(dbg, 0, is_info, &cu_die, &error) == DW_DLV_OK) {
                std::string currentFile, comp_dir;
                char* cu_name = 0;
                if (dwarf_diename(cu_die, &cu_name, &error) == DW_DLV_OK && cu_name) {
                    currentFile = cu_name;
                    dwarf_dealloc(dbg, cu_name, DW_DLA_STRING);
                }

                Dwarf_Attribute comp_dir_attr = 0;
                if (dwarf_attr(cu_die, DW_AT_comp_dir, &comp_dir_attr, &error) == DW_DLV_OK) {
                    char* dir_name = 0;
                    if (dwarf_formstring(comp_dir_attr, &dir_name, &error) == DW_DLV_OK && dir_name) {
                        comp_dir = dir_name;
                        dwarf_dealloc(dbg, dir_name, DW_DLA_STRING);
                    }
                    dwarf_dealloc_attribute(comp_dir_attr);
                }

                if (!comp_dir.empty() && !currentFile.empty()) {
                    compDirMap[currentFile] = comp_dir;
                }

                DPRINTF("Processing CU: %s (comp_dir: %s, version: %d)",
                        currentFile.c_str(), comp_dir.c_str(), version);

                ProcessDIE(cu_die, currentFile, comp_dir);
                dwarf_dealloc_die(cu_die);
            }
            if (error) dwarf_dealloc_error(dbg, error);
        }
    }

    // Processes DIE and its children iteratively
    void ProcessDIE(Dwarf_Die die, const std::string& currentFile, const std::string& comp_dir) {
        Dwarf_Error error = 0;
        std::vector<Dwarf_Die> die_stack;
        die_stack.reserve(64);
        die_stack.push_back(die);

        while (!die_stack.empty()) {
            Dwarf_Die current_die = die_stack.back();
            die_stack.pop_back();

            Dwarf_Half tag = 0;
            if (dwarf_tag(current_die, &tag, &error) != DW_DLV_OK) {
                if (error) dwarf_dealloc_error(dbg, error);
                continue;
            }

            if (IsSymbolTag(tag)) {
                char* name = nullptr;
                if (dwarf_diename(current_die, &name, &error) == DW_DLV_OK && name && IsValidSymbolName(name)) {
                    std::string symbolName(name);
                    dwarf_dealloc(dbg, name, DW_DLA_STRING);
                    if (IsFunctionTag(tag)) {
                        ProcessFunctionDIE(current_die, tag, symbolName, currentFile, comp_dir, &error);
                    } else {
                        ProcessVariableDIE(current_die, tag, symbolName, currentFile, comp_dir, &error);
                    }
                } else if (name) {
                    dwarf_dealloc(dbg, name, DW_DLA_STRING);
                }
            }

            std::vector<Dwarf_Die> children;
            children.reserve(16);
            Dwarf_Die child_die = nullptr;
            if (dwarf_child(current_die, &child_die, &error) == DW_DLV_OK) {
                children.push_back(child_die);
                Dwarf_Die sibling_die = nullptr;
                while (dwarf_siblingof_b(dbg, child_die, TRUE, &sibling_die, &error) == DW_DLV_OK) {
                    children.push_back(sibling_die);
                    child_die = sibling_die;
                }
            }

            for (auto it = children.rbegin(); it != children.rend(); ++it) {
                die_stack.push_back(*it);
            }

            if (error) dwarf_dealloc_error(dbg, error);
        }
    }

    // Processes function/subroutine DIE
    void ProcessFunctionDIE(Dwarf_Die die, Dwarf_Half tag, const std::string& symbolName,
                           const std::string& currentFile, const std::string& comp_dir, Dwarf_Error* error) {
        Dwarf_Attribute attr = nullptr;
        if (dwarf_attr(die, DW_AT_low_pc, &attr, error) != DW_DLV_OK) return;
        DwarfAttributeGuard guard(attr);

        Dwarf_Addr low_pc = 0;
        if (dwarf_formaddr(attr, &low_pc, error) != DW_DLV_OK || low_pc == 0) return;

        const duint adjusted_addr = addressCache.TranslateAddress(static_cast<duint>(low_pc));
        if (modSize > 0 && !FileHandler::IsValidModuleAddress(adjusted_addr, runtimeBase, modSize)) {
            DPRINTF("Skipped function %s: address 0x%llX outside module range",
                    symbolName.c_str(), adjusted_addr);
            return;
        }

        const duint symbolSize = GetFunctionSize(die, error);
        if (!IsValidFunctionSize(symbolSize)) {
            DPRINTF("Skipped function %s: invalid size %llu", symbolName.c_str(), symbolSize);
            return;
        }

        duint endAddress = adjusted_addr + symbolSize;
        if (modSize > 0 && endAddress > runtimeBase + modSize) {
            endAddress = runtimeBase + modSize;
        }

        Symbol symbol = {
            FileHandler::CleanSymbolName(symbolName), adjusted_addr, true, symbolSize, endAddress,
            currentFile, "", {LocationInfo::INVALID, 0, 0, 0, {}}, "", 0, false, ""
        };

        ProcessAdditionalAttributes(die, symbol, comp_dir, error);
        loadedSymbols.push_back(std::move(symbol));
        DPRINTF("Added function: %s at 0x%llX (size: %llu, type: %s)",
                symbol.name.c_str(), adjusted_addr, symbolSize, symbol.type.c_str());
    }

    // Processes variable/parameter DIE
    void ProcessVariableDIE(Dwarf_Die die, Dwarf_Half tag, const std::string& symbolName,
                           const std::string& currentFile, const std::string& comp_dir, Dwarf_Error* error) {
        Symbol symbol = {
            FileHandler::CleanSymbolName(symbolName), 0, false, 0, 0, currentFile, "",
            {LocationInfo::INVALID, 0, 0, 0, {}}, "", 0, false, ""
        };

        ProcessAdditionalAttributes(die, symbol, comp_dir, error);
        if (symbol.location.type != LocationInfo::INVALID) {
            loadedSymbols.push_back(std::move(symbol));
            DPRINTF("Added variable: %s (type: %s)", symbol.name.c_str(), symbol.type.c_str());
        }
    }

    // Parses DWARF line information
    void ParseLineInfo() {
        Dwarf_Error error = 0;
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

        while (dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version, &abbrev_offset,
                                      &address_size, &offset_size, &extension_size, &signature,
                                      &typeoffset, &next_cu_header, &header_cu_type, &error) == DW_DLV_OK) {
            Dwarf_Die cu_die = 0;
            if (dwarf_siblingof_b(dbg, 0, is_info, &cu_die, &error) == DW_DLV_OK) {
                Dwarf_Unsigned line_version = 0;
                Dwarf_Small table_type = 0;
                Dwarf_Line_Context line_context = 0;
                if (dwarf_srclines_b(cu_die, &line_version, &table_type, &line_context, &error) == DW_DLV_OK) {
                    Dwarf_Line* linebuf = 0;
                    Dwarf_Signed linecount = 0;
                    if (dwarf_srclines_from_linecontext(line_context, &linebuf, &linecount, &error) == DW_DLV_OK) {
                        for (Dwarf_Signed i = 0; i < linecount; ++i) {
                            Dwarf_Addr lineaddr = 0;
                            char* filename = 0;
                            Dwarf_Unsigned lineno = 0;
                            if (dwarf_lineaddr(linebuf[i], &lineaddr, &error) == DW_DLV_OK &&
                                dwarf_linesrc(linebuf[i], &filename, &error) == DW_DLV_OK &&
                                dwarf_lineno(linebuf[i], &lineno, &error) == DW_DLV_OK) {
                                if (lineaddr != 0 && filename && lineno != 0) {
                                    duint adjusted_addr = dwarfImageBase ?
                                        (static_cast<duint>(lineaddr) - dwarfImageBase) + runtimeBase :
                                        static_cast<duint>(lineaddr) + runtimeBase;

                                    if (modSize == 0 || FileHandler::IsValidModuleAddress(adjusted_addr, runtimeBase, modSize)) {
                                        lineInfos.push_back({std::string(filename), static_cast<unsigned int>(lineno), adjusted_addr});
                                        DPRINTF("Line info: %s:%u at DWARF addr 0x%llX -> runtime addr 0x%llX",
                                                filename, lineno, lineaddr, adjusted_addr);
                                    }
                                }
                                if (filename) dwarf_dealloc(dbg, filename, DW_DLA_STRING);
                            }
                        }
                        dwarf_srclines_dealloc_b(line_context);
                    }
                }
                dwarf_dealloc_die(cu_die);
            }
            if (error) dwarf_dealloc_error(dbg, error);
        }
        DPRINTF("ParseDWARFLineInfo: Loaded %zu line entries", lineInfos.size());
    }

    // Parses COFF symbols as a fallback
    void ParseCOFFSymbols(const std::filesystem::path& path) {
        DPUTS("Entering ParseCOFFSymbols");
        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            fileData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        const IMAGE_FILE_HEADER* fileHeader = &ntHeaders->FileHeader;
        if (fileHeader->NumberOfSymbols == 0 || fileHeader->PointerToSymbolTable == 0) return;

        const IMAGE_SYMBOL* symbolTable = reinterpret_cast<const IMAGE_SYMBOL*>(
            fileData.data() + fileHeader->PointerToSymbolTable);
        const char* stringTable = fileData.data() + fileHeader->PointerToSymbolTable +
                                fileHeader->NumberOfSymbols * sizeof(IMAGE_SYMBOL);
        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);

        std::unordered_set<std::string> existingNames;
        std::unordered_set<duint> existingAddresses;
        for (const auto& sym : loadedSymbols) {
            existingNames.insert(sym.name);
            if (sym.address != 0) existingAddresses.insert(sym.address);
        }

        for (DWORD i = 0; i < fileHeader->NumberOfSymbols; ++i) {
            const IMAGE_SYMBOL& sym = symbolTable[i];
            std::string name = sym.N.Name.Short ? 
                std::string(reinterpret_cast<const char*>(sym.N.ShortName), 8) :
                std::string(stringTable + sym.N.Name.Long);
            name = name.c_str(); // Trim null characters

            if (name.empty() || name[0] == '.' || name.find("__") == 0 ||
                sym.SectionNumber <= 0 || sym.SectionNumber > fileHeader->NumberOfSections ||
                (sym.StorageClass == IMAGE_SYM_CLASS_STATIC && sym.Value == 0)) {
                i += sym.NumberOfAuxSymbols;
                continue;
            }

            const IMAGE_SECTION_HEADER& section = sections[sym.SectionNumber - 1];
            duint address = addressCache.TranslateAddress(sym.Value + section.VirtualAddress + dwarfImageBase);
            if (modSize > 0 && !FileHandler::IsValidModuleAddress(address, runtimeBase, modSize)) {
                i += sym.NumberOfAuxSymbols;
                continue;
            }

            if (existingNames.count(name) || existingAddresses.count(address)) {
                i += sym.NumberOfAuxSymbols;
                continue;
            }

            bool isFunction = (sym.Type & 0x20) != 0 && (section.Characteristics & IMAGE_SCN_MEM_EXECUTE);
            Symbol symbol = {
                FileHandler::CleanSymbolName(name), address, isFunction, 0, address, "",
                isFunction ? "function" : "data", {LocationInfo::INVALID, 0, 0, 0, {}},
                "", 0, (sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL), name
            };

            loadedSymbols.push_back(symbol);
            existingNames.insert(symbol.name);
            existingAddresses.insert(symbol.address);
            DPRINTF("Added COFF symbol: %s at 0x%llX (%s)", symbol.name.c_str(), symbol.address, isFunction ? "function" : "data");
            i += sym.NumberOfAuxSymbols;
        }
        DPRINTF("ParseCOFFSymbols: Loaded %zu COFF symbols", loadedSymbols.size());
    }

    // Calculates function size from DWARF attributes
    duint GetFunctionSize(Dwarf_Die die, Dwarf_Error* error) {
        duint size = 0;
        Dwarf_Attribute high_pc_attr = 0;
        if (dwarf_attr(die, DW_AT_high_pc, &high_pc_attr, error) == DW_DLV_OK) {
            DwarfAttributeGuard guard(high_pc_attr);
            Dwarf_Half form = 0;
            if (dwarf_whatform(high_pc_attr, &form, error) == DW_DLV_OK) {
                if (form == DW_FORM_addr) {
                    Dwarf_Addr high_pc = 0;
                    if (dwarf_formaddr(high_pc_attr, &high_pc, error) == DW_DLV_OK && high_pc > 0) {
                        size = static_cast<duint>(high_pc - addressCache.TranslateAddress(high_pc));
                    }
                }
                else if (form == DW_FORM_data1 || form == DW_FORM_data2 ||
                         form == DW_FORM_data4 || form == DW_FORM_data8 ||
                         form == DW_FORM_udata) {
                    Dwarf_Unsigned offset = 0;
                    if (dwarf_formudata(high_pc_attr, &offset, error) == DW_DLV_OK) {
                        size = static_cast<duint>(offset);
                    }
                }
            }
        }

        if (size == 0) {
            Dwarf_Attribute size_attr = 0;
            if (dwarf_attr(die, DW_AT_byte_size, &size_attr, error) == DW_DLV_OK) {
                DwarfAttributeGuard guard(size_attr);
                Dwarf_Unsigned size_val = 0;
                if (dwarf_formudata(size_attr, &size_val, error) == DW_DLV_OK) {
                    size = static_cast<duint>(size_val);
                }
            }
        }

        return size ? size : 0x20;
    }

    // Processes additional DIE attributes
    void ProcessAdditionalAttributes(Dwarf_Die die, Symbol& symbol, const std::string& comp_dir, Dwarf_Error* error) {
        symbol.compDir = comp_dir;
        symbol.type = GetTypeInfo(die);

        Dwarf_Attribute line_attr = 0;
        if (dwarf_attr(die, DW_AT_decl_line, &line_attr, error) == DW_DLV_OK) {
            DwarfAttributeGuard guard(line_attr);
            Dwarf_Unsigned line_no = 0;
            if (dwarf_formudata(line_attr, &line_no, error) == DW_DLV_OK) {
                symbol.line = static_cast<int>(line_no);
            }
        }

        Dwarf_Attribute linkage_attr = 0;
        if (dwarf_attr(die, DW_AT_linkage_name, &linkage_attr, error) == DW_DLV_OK ||
            dwarf_attr(die, DW_AT_MIPS_linkage_name, &linkage_attr, error) == DW_DLV_OK) {
            DwarfAttributeGuard guard(linkage_attr);
            char* linkage_name = 0;
            if (dwarf_formstring(linkage_attr, &linkage_name, error) == DW_DLV_OK && linkage_name) {
                symbol.linkageName = linkage_name;
                dwarf_dealloc(dbg, linkage_name, DW_DLA_STRING);
            }
        }

        Dwarf_Attribute external_attr = 0;
        if (dwarf_attr(die, DW_AT_external, &external_attr, error) == DW_DLV_OK) {
            DwarfAttributeGuard guard(external_attr);
            Dwarf_Bool is_external = 0;
            if (dwarf_formflag(external_attr, &is_external, error) == DW_DLV_OK) {
                symbol.isExternal = (is_external != 0);
            }
        }

        Dwarf_Attribute location_attr = 0;
        if (dwarf_attr(die, DW_AT_location, &location_attr, error) == DW_DLV_OK) {
            DwarfAttributeGuard guard(location_attr);
            symbol.location = ProcessLocationExpression(location_attr);
        }
    }

    // Processes DWARF location expressions
    LocationInfo ProcessLocationExpression(Dwarf_Attribute attr) {
        LocationInfo loc = {LocationInfo::INVALID, 0, 0, 0, {}};
        Dwarf_Error error = 0;

        Dwarf_Loc_Head_c loclist_head = 0;
        Dwarf_Unsigned listlen = 0;
        if (dwarf_get_loclist_c(attr, &loclist_head, &listlen, &error) == DW_DLV_OK) {
            for (Dwarf_Unsigned i = 0; i < listlen; ++i) {
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

                if (dwarf_get_locdesc_entry_e(loclist_head, i, &lle_value, &rawlowpc, &rawhipc,
                                              &debug_addr_unavailable, &lowpc, &hipc, &expr_ops_count,
                                              &locdesc_offset, &locentry, &loclist_source,
                                              &dw_expression_offset_out, &dw_entry_len_out, &error) == DW_DLV_OK) {
                    if (expr_ops_count > 0) {
                        Dwarf_Small op = 0;
                        Dwarf_Unsigned opd1 = 0, opd2 = 0, opd3 = 0;
                        Dwarf_Unsigned offset_for_branch = 0;
                        if (dwarf_get_location_op_value_c(locentry, 0, &op, &opd1, &opd2, &opd3, &offset_for_branch, &error) == DW_DLV_OK) {
                            loc.type = LocationInfo::EXPRESSION;
                            loc.expression.push_back(op);
                            switch (op) {
                                case DW_OP_addr: loc.type = LocationInfo::ADDRESS; loc.address = addressCache.TranslateAddress(static_cast<duint>(opd1)); break;
                                case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
                                case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
                                case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
                                case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
                                case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
                                case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
                                case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
                                case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
                                    loc.type = LocationInfo::REGISTER; loc.reg = op - DW_OP_reg0; break;
                                case DW_OP_regx: loc.type = LocationInfo::REGISTER; loc.reg = static_cast<int>(opd1); break;
                                case DW_OP_fbreg: loc.type = LocationInfo::STACK_OFFSET; loc.offset = static_cast<int>(opd1); break;
                                case DW_OP_breg0: case DW_OP_breg1: case DW_OP_breg2: case DW_OP_breg3:
                                case DW_OP_breg4: case DW_OP_breg5: case DW_OP_breg6: case DW_OP_breg7:
                                case DW_OP_breg8: case DW_OP_breg9: case DW_OP_breg10: case DW_OP_breg11:
                                case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
                                case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
                                case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
                                case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
                                case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31:
                                    loc.type = LocationInfo::STACK_OFFSET; loc.reg = op - DW_OP_breg0; loc.offset = static_cast<int>(opd1); break;
                                case DW_OP_bregx: loc.type = LocationInfo::STACK_OFFSET; loc.reg = static_cast<int>(opd1); loc.offset = static_cast<int>(opd2); break;
                            }
                            break;
                        }
                    }
                }
            }
            dwarf_dealloc_loc_head_c(loclist_head);
        }
        else {
            Dwarf_Ptr expr_bytes = 0;
            Dwarf_Unsigned expr_len = 0;
            if (dwarf_formexprloc(attr, &expr_len, &expr_bytes, &error) == DW_DLV_OK && expr_len > 0 && expr_bytes) {
                uint8_t* bytes = static_cast<uint8_t*>(expr_bytes);
                loc.expression.assign(bytes, bytes + expr_len);
                uint8_t op = bytes[0];
                loc.type = LocationInfo::EXPRESSION;
                if (op == DW_OP_addr && expr_len >= 1 + sizeof(duint)) {
                    loc.type = LocationInfo::ADDRESS;
                    loc.address = addressCache.TranslateAddress(*reinterpret_cast<duint*>(bytes + 1));
                }
                else if (op == DW_OP_fbreg && expr_len >= 2) {
                    loc.type = LocationInfo::STACK_OFFSET;
                    loc.offset = static_cast<int8_t>(bytes[1]);
                }
            }
            else {
                Dwarf_Block* block = 0;
                if (dwarf_formblock(attr, &block, &error) == DW_DLV_OK && block && block->bl_len > 0 && block->bl_data) {
                    uint8_t* bytes = static_cast<uint8_t*>(block->bl_data);
                    loc.expression.assign(bytes, bytes + block->bl_len);
                    uint8_t op = bytes[0];
                    loc.type = LocationInfo::EXPRESSION;
                    if (op == DW_OP_addr && block->bl_len >= 1 + sizeof(duint)) {
                        loc.type = LocationInfo::ADDRESS;
                        loc.address = addressCache.TranslateAddress(*reinterpret_cast<duint*>(bytes + 1));
                    }
                    else if (op == DW_OP_fbreg && block->bl_len >= 2) {
                        loc.type = LocationInfo::STACK_OFFSET;
                        loc.offset = static_cast<int8_t>(bytes[1]);
                    }
                    dwarf_dealloc(dbg, block, DW_DLA_BLOCK);
                }
            }
        }
        return loc;
    }

    // Retrieves type information from DIE
    std::string GetTypeInfo(Dwarf_Die die) {
        Dwarf_Error error = 0;
        Dwarf_Attribute type_attr = 0;
        if (dwarf_attr(die, DW_AT_type, &type_attr, &error) == DW_DLV_OK) {
            DwarfAttributeGuard guard(type_attr);
            Dwarf_Off type_offset = 0;
            if (dwarf_global_formref(type_attr, &type_offset, &error) == DW_DLV_OK) {
                auto it = typeMap.find(type_offset);
                if (it != typeMap.end()) {
                    return it->second.name;
                }

                Dwarf_Die type_die = 0;
                if (dwarf_offdie_b(dbg, type_offset, TRUE, &type_die, &error) == DW_DLV_OK) {
                    char* type_name = 0;
                    std::string result = "unknown";
                    if (dwarf_diename(type_die, &type_name, &error) == DW_DLV_OK && type_name) {
                        result = type_name;
                        dwarf_dealloc(dbg, type_name, DW_DLA_STRING);
                    }
                    else {
                        Dwarf_Half tag = 0;
                        if (dwarf_tag(type_die, &tag, &error) == DW_DLV_OK) {
                            switch (tag) {
                                case DW_TAG_base_type: result = "base_type"; break;
                                case DW_TAG_pointer_type: result = "pointer"; break;
                                case DW_TAG_array_type: result = "array"; break;
                                case DW_TAG_structure_type: result = "struct"; break;
                                case DW_TAG_union_type: result = "union"; break;
                                case DW_TAG_enumeration_type: result = "enum"; break;
                                case DW_TAG_typedef: result = "typedef"; break;
                                case DW_TAG_const_type: result = "const"; break;
                                case DW_TAG_volatile_type: result = "volatile"; break;
                                case DW_TAG_subroutine_type: result = "function"; break;
                            }
                        }
                    }
                    TypeInfo typeInfo = {result, 0, "", 0, {}};
                    typeMap[type_offset] = typeInfo;
                    dwarf_dealloc_die(type_die);
                    return result;
                }
            }
        }
        return "";
    }

    duint runtimeBase;
    duint modSize;
    duint dwarfImageBase;
    std::vector<Symbol> loadedSymbols;
    std::vector<LineInfo> lineInfos;
    std::map<Dwarf_Off, TypeInfo> typeMap;
    std::map<std::string, std::string> compDirMap;
    AddressTranslator addressCache;
    Dwarf_Debug dbg = nullptr;
    std::vector<char> fileData;
};

// Manages symbol integration into x64dbg
class SymbolManager {
public:
    SymbolManager(duint runtimeBase) : runtimeBase(runtimeBase) {
        loadedSymbols.reserve(10000); // Reserve space to reduce reallocations
    }

    // Adds parsed symbols to x64dbg
    void AddSymbols(const std::vector<Symbol>& symbols) {
        if (symbols.empty()) {
            MessageBoxA(NULL, "No symbols to load.", "DWARFHelper", MB_OK | MB_ICONWARNING);
            return;
        }

        for (const auto& sym : symbols) {
            if (sym.address == 0 && sym.location.type == LocationInfo::INVALID) continue;
            if (sym.address != 0) AddLabel(sym);
            if (!sym.fileName.empty() || !sym.type.empty() || sym.location.type != LocationInfo::INVALID) {
                AddComment(sym);
            }
            if (sym.isFunction && sym.size > 0 && sym.address != 0) AddFunction(sym);
            if (!sym.type.empty()) typeCount++;
        }

        GuiUpdateAllViews();
        ShowResults(symbols.size());
    }

private:
    // Sets a label for a symbol
    void AddLabel(const Symbol& sym) {
        char existingLabel[MAX_LABEL_SIZE] = "";
        bool hasExisting = DbgGetLabelAt(sym.address, SEG_DEFAULT, existingLabel) && strlen(existingLabel) > 0;
        if (!hasExisting && DbgSetLabelAt(sym.address, sym.name.c_str())) {
            labelCount++;
            DPRINTF("Set label: %s at 0x%llX", sym.name.c_str(), sym.address);
        }
    }

    // Adds a comment for a symbol
    void AddComment(const Symbol& sym) {
        std::string filename = sym.fileName;
        size_t lastSlash = filename.find_last_of("/\\");
        if (lastSlash != std::string::npos) filename = filename.substr(lastSlash + 1);

        char comment[1024] = "";
        if (sym.location.type == LocationInfo::ADDRESS) {
            snprintf(comment + strlen(comment), sizeof(comment) - strlen(comment), " @0x%llX", sym.location.address);
        }
        else if (sym.location.type == LocationInfo::REGISTER) {
            snprintf(comment + strlen(comment), sizeof(comment) - strlen(comment), " reg%d", sym.location.reg);
        }
        else if (sym.location.type == LocationInfo::STACK_OFFSET) {
            snprintf(comment + strlen(comment), sizeof(comment) - strlen(comment), " [%+d]", sym.location.offset);
        }

        if (sym.isFunction) {
            std::string lineStr = (sym.line > 0) ? (":" + std::to_string(sym.line)) : "";
            snprintf(comment, sizeof(comment),
                     "Function: %s%s%s (size: %llu)%s%s%s - %s%s",
                     sym.name.c_str(), sym.type.empty() ? "" : " -> ", sym.type.c_str(),
                     sym.size, sym.linkageName.empty() ? "" : " [", sym.linkageName.c_str(),
                     sym.linkageName.empty() ? "" : "]", filename.c_str(), lineStr.c_str());
        }
        else {
            std::string symStr = (sym.line > 0) ? (":" + std::to_string(sym.line)) : "";
            snprintf(comment, sizeof(comment),
                     "Symbol: %s%s%s%s%s - %s%s",
                     sym.name.c_str(), sym.type.empty() ? "" : " (", sym.type.c_str(),
                     sym.type.empty() ? "" : ")", comment, filename.c_str(), symStr.c_str());
        }

        if (sym.address != 0) {
            char existingComment[1024] = "";
            bool hasComment = DbgGetCommentAt(sym.address, existingComment) && strlen(existingComment) > 0;
            if (hasComment) {
                char newComment[2048] = "";
                snprintf(newComment, sizeof(newComment), "%s\n%s", existingComment, comment);
                if (DbgSetCommentAt(sym.address, newComment)) {
                    commentCount++;
                    DPRINTF("Appended comment for %s at 0x%llX", sym.name.c_str(), sym.address);
                }
            }
            else if (DbgSetCommentAt(sym.address, comment)) {
                commentCount++;
                DPRINTF("Set comment for %s at 0x%llX", sym.name.c_str(), sym.address);
            }
        }
    }

    // Adds a function definition
    void AddFunction(const Symbol& sym) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (VirtualQuery((LPCVOID)sym.address, &mbi, sizeof(mbi))) {
            bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool isCommitted = (mbi.State == MEM_COMMIT);
            if (isCommitted && isExecutable) {
                DbgFunctionDel(sym.address);
                if (DbgFunctionAdd(sym.address, sym.endAddress)) {
                    functionCount++;
                    DPRINTF("Created function: %s at 0x%llX-0x%llX", sym.name.c_str(), sym.address, sym.endAddress);
                }
            }
        }
    }

    // Displays results of symbol loading
    void ShowResults(size_t totalSymbols) {
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
                 labelCount, totalSymbols, functionCount, commentCount, typeCount, compDirMap.size());
        MessageBoxA(NULL, msg, "DWARFHelper", MB_OK | MB_ICONINFORMATION);
        DPRINTF("LoadSymbols completed: %d labels, %d functions, %d comments, %d types",
                labelCount, functionCount, commentCount, typeCount);
    }

    duint runtimeBase;
    int labelCount = 0;
    int functionCount = 0;
    int commentCount = 0;
    int typeCount = 0;
    std::vector<Symbol> loadedSymbols;
    std::map<std::string, std::string> compDirMap;
};

// Manages user interface interactions
class UiManager {
public:
    // Initializes plugin menu entries
    static void InitializeMenu(PLUG_SETUPSTRUCT* setupStruct) {
        menuHandleLabelsDWARF = _plugin_menuaddentry(setupStruct->hMenu, MA_LABELS_DWARF, "Load DWARF Symbols from File");
        menuHandleAbout = _plugin_menuaddentry(setupStruct->hMenu, MA_ABOUT, "About");
    }

    // Handles menu actions
    static void HandleMenuAction(int menuEntry) {
        switch (menuEntry) {
            case MA_LABELS_DWARF: LoadSymbolsFromFile(); break;
            case MA_ABOUT: ShowAboutDialog(); break;
        }
        GuiUpdateDisassemblyView();
    }

private:
    // Loads symbols from a selected file
    static void LoadSymbolsFromFile() {
        if (!DbgIsDebugging()) {
            MessageBoxA(NULL, "No process is being debugged.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            return;
        }

        auto runtimeBase = FileHandler::GetModuleBase();
        if (!runtimeBase) {
            MessageBoxA(NULL, "Failed to get module base.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            return;
        }

        auto filePath = FileHandler::OpenFileDialog(runtimeBase);
        if (!filePath) return;

        DwarfParser parser(runtimeBase);
        if (parser.ParseFile(*filePath)) {
            SymbolManager manager(runtimeBase);
            manager.AddSymbols(parser.GetSymbols());
        }
    }

    // Displays the about dialog
    static void ShowAboutDialog() {
        MessageBoxA(NULL, "DWARFHelper Plugin v1.1 \nLoad DWARF symbols as labels\n By CynicRus", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
    }

    static int menuHandleLabelsDWARF;
    static int menuHandleAbout;
};

int UiManager::menuHandleLabelsDWARF = 0;
int UiManager::menuHandleAbout = 0;

// Core plugin functionality
class PluginCore {
public:
    // Initializes the plugin
    static bool Initialize(PLUG_INITSTRUCT* initStruct) {
        initStruct->pluginVersion = PLUGIN_VERSION;
        initStruct->sdkVersion = PLUG_SDKVERSION;
        strncpy_s(initStruct->pluginName, PLUGIN_NAME, sizeof(initStruct->pluginName));
        pluginHandle = initStruct->pluginHandle;
        DPRINTF("Plugin initialized: handle=%d, version=%d, sdkVersion=%d", pluginHandle, PLUGIN_VERSION, PLUG_SDKVERSION);
        return true;
    }

    // Sets up the plugin
    static void Setup(PLUG_SETUPSTRUCT* setupStruct) {
        hwndDlg = setupStruct->hwndDlg;
        UiManager::InitializeMenu(setupStruct);
    }

    // Shuts down the plugin
    static bool Shutdown() {
        _plugin_menuclear(pluginHandle);
        return true;
    }

private:
    static int pluginHandle;
    static HWND hwndDlg;
};

int PluginCore::pluginHandle = 0;
HWND PluginCore::hwndDlg = nullptr;

// Plugin entry points
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    return PluginCore::Initialize(initStruct);
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    PluginCore::Setup(setupStruct);
}

PLUG_EXPORT bool plugstop() {
    return PluginCore::Shutdown();
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info) {
    if (cbType == CB_MENUENTRY && info) {
        UiManager::HandleMenuAction(info->hEntry);
    }
}

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE hinstDLL, [[maybe_unused]] DWORD fdwReason, [[maybe_unused]] LPVOID lpvReserved) {
    return TRUE;
}
