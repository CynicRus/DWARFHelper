#include <windows.h>
#include <Psapi.h>
#include <ShObjIdl.h>
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
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
// #define DEBUG
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
struct Symbol
{
    std::string name;
    duint address;
    bool isFunction;
    duint size;
    duint endAddress;
    std::string fileName;  
};
// Structure to hold line information
struct LineInfo
{
    std::string file;
    unsigned int line;
    duint address;
};

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
        // If no base translation needed
        if (imageBase == 0 && runtimeBase == 0) {
            return dwarf_addr;
        }
        
        auto it = dwarfToRuntime.find(dwarf_addr);
        if (it != dwarfToRuntime.end()) {
            return it->second;
        }

        // Simple offset-based translation
        duint runtime_addr = (dwarf_addr - imageBase) + runtimeBase;
        dwarfToRuntime[dwarf_addr] = runtime_addr;
        DPRINTF("Translated address: 0x%llX -> 0x%llX", dwarf_addr, runtime_addr);
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

    if (dosHeader->e_lfanew >= imageSize || dosHeader->e_lfanew < 0)
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

// Validate address within module bounds
static bool IsValidModuleAddress(duint address, duint modBase, duint modSize)
{
    return address >= modBase && address < modBase + modSize;
}

// Utility to clean symbol names for x64dbg compatibility
static std::string CleanSymbolName(const std::string &name)
{
    std::string cleaned = name;
    // Replace invalid characters (e.g., '$', ':') with '_'
    for (char &c : cleaned)
    {
        if (c == '$' || c == ':' || c == '@' || (!std::isalnum(c) && c != '_'))
        {
            c = '_';
        }
    }
    // Remove leading/trailing underscores
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

    // Try to get high_pc attribute first
    Dwarf_Attribute high_pc_attr = 0;
    if (dwarf_attr(function_die, DW_AT_high_pc, &high_pc_attr, error) == DW_DLV_OK)
    {
        Dwarf_Half form = 0;
        if (dwarf_whatform(high_pc_attr, &form, error) == DW_DLV_OK)
        {
            if (form == DW_FORM_addr)
            {
                // high_pc is an absolute address
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
                // high_pc is an offset from low_pc
                Dwarf_Unsigned offset = 0;
                if (dwarf_formudata(high_pc_attr, &offset, error) == DW_DLV_OK)
                {
                    size = static_cast<duint>(offset);
                }
            }
        }
        dwarf_dealloc_attribute(high_pc_attr);
    }

    // If we couldn't get the size from high_pc, try byte_size attribute
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

    // Use default minimum size for functions if we can't determine it
    if (size == 0)
    {
        size = 0x20; // Minimum 32 bytes for functions
        DPRINTF("Using default size %llu for function at 0x%llX", size, low_pc);
    }

    return size;
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

// Recursively process DIE and its children
void ProcessDIE(Dwarf_Debug dbg, Dwarf_Die die, std::vector<Symbol> &loadedSymbols,
                duint runtimeBase, duint modSize, Dwarf_Bool is_info, const std::string &currentFile = "")
{
    Dwarf_Error error = 0;

    Dwarf_Half tag = 0;
    if (dwarf_tag(die, &tag, &error) != DW_DLV_OK)
    {
        if (error)
            dwarf_dealloc_error(dbg, error);
        return;
    }

    // Handle different DIE types
    if (tag == DW_TAG_subprogram || tag == DW_TAG_variable ||
        tag == DW_TAG_label || tag == DW_TAG_formal_parameter ||
        tag == DW_TAG_enumerator)
    {
        char *name = 0;
        if (dwarf_diename(die, &name, &error) == DW_DLV_OK && name && strlen(name) > 0)
        {
            std::string symbolName = name;
            dwarf_dealloc(dbg, name, DW_DLA_STRING);

            // Skip compiler-generated or unnamed symbols
            if (symbolName.find("__") == 0 || symbolName.empty())
            {
                return;
            }

            Dwarf_Addr low_pc = 0;
            Dwarf_Attribute attr = 0;

            // Try to get address information
            if (dwarf_attr(die, DW_AT_low_pc, &attr, &error) == DW_DLV_OK)
            {
                if (dwarf_formaddr(attr, &low_pc, &error) == DW_DLV_OK && low_pc != 0)
                {
                    duint adjusted_addr = g_addressCache.TranslateAddress(static_cast<duint>(low_pc));

                    // Validate address is within module bounds
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

                    // Handle functions specially
                    if (tag == DW_TAG_subprogram)
                    {
                        symbolSize = GetFunctionSize(die, dbg, low_pc, &error);
                        endAddress = adjusted_addr + symbolSize;

                        // Validate function bounds
                        if (modSize > 0 && endAddress > runtimeBase + modSize)
                        {
                            endAddress = runtimeBase + modSize;
                            symbolSize = endAddress - adjusted_addr;
                        }
                    }

                    loadedSymbols.push_back({cleaned_name,
                                             adjusted_addr,
                                             tag == DW_TAG_subprogram,
                                             symbolSize,
                                             endAddress,
                                             currentFile});

                    DPRINTF("Added %s symbol: %s at 0x%llX (size: %llu)",
                            tag == DW_TAG_subprogram ? "function" : "symbol",
                            cleaned_name.c_str(), adjusted_addr, symbolSize);
                }
                dwarf_dealloc_attribute(attr);
            }
            // Handle variables with location information
            else if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter)
            {
                Dwarf_Attribute location_attr = 0;
                if (dwarf_attr(die, DW_AT_location, &location_attr, &error) == DW_DLV_OK)
                {
                    // Handle location expressions - simplified for now
                    // Could be expanded to handle DW_OP_addr, DW_OP_fbreg, etc.
                    dwarf_dealloc_attribute(location_attr);
                }
            }
        }
    }

    // Recursively process children
    Dwarf_Die child_die = 0;
    if (dwarf_child(die, &child_die, &error) == DW_DLV_OK)
    {
        ProcessDIE(dbg, child_die, loadedSymbols, runtimeBase, modSize, is_info, currentFile);

        // Process siblings
        Dwarf_Die sibling_die = 0;
        while (dwarf_siblingof_b(dbg, child_die, is_info, &sibling_die, &error) == DW_DLV_OK)
        {
            dwarf_dealloc_die(child_die);
            child_die = sibling_die;
            ProcessDIE(dbg, child_die, loadedSymbols, runtimeBase, modSize, is_info, currentFile);
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
        // Get module information
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

        // Initialize DWARF
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

        // Read file to get image base
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

        // Process compilation units
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
                // Get compilation unit name for context
                char *cu_name = 0;
                std::string currentFile;
                if (dwarf_diename(cu_die, &cu_name, &error) == DW_DLV_OK && cu_name)
                {
                    currentFile = cu_name;
                    dwarf_dealloc(dbg, cu_name, DW_DLA_STRING);
                }

                ProcessDIE(dbg, cu_die, loadedSymbols, runtimeBase, modSize, is_info, currentFile);
                dwarf_dealloc_die(cu_die);
            }
        }

        // Process line information
        auto lineInfos = ParseDWARFLineInfo(dbg, dwarfImageBase, runtimeBase, modSize);
        DPRINTF("Processed %zu line info entries", lineInfos.size());

        dwarf_finish(dbg);

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

void LoadSymbols(duint runtimeBase, const std::vector<Symbol> &loadedSymbols)
{
    DPUTS("Entering LoadSymbols");
    DPRINTF("Runtime base: 0x%llX, Symbols count: %zu", runtimeBase, loadedSymbols.size());

    if (loadedSymbols.empty())
    {
        MessageBoxA(NULL, "No symbols to load.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        return;
    }

    int labelCount = 0;
    int functionCount = 0;
    int commentCount = 0;

    // Clear existing user labels first (optional)
    // DbgClearLabelRange(runtimeBase, runtimeBase + modSize);

    // First pass: Set all labels and comments
    for (const auto &sym : loadedSymbols)
    {
        // Set label
        if (DbgSetLabelAt(sym.address, sym.name.c_str()))
        {
            labelCount++;
            DPRINTF("Set label: %s at 0x%llX", sym.name.c_str(), sym.address);
        }
        else
        {
            DPRINTF("Failed to set label: %s at 0x%llX", sym.name.c_str(), sym.address);
        }

        // Set comment with additional info
        if (!sym.fileName.empty())
        {
            std::string filename = sym.fileName;
            size_t lastSlash = filename.find_last_of("/\\");
            if (lastSlash != std::string::npos)
            {
                filename = filename.substr(lastSlash + 1);
            }

            char comment[512];
            if (sym.isFunction)
            {
                snprintf(comment, sizeof(comment), "Function: %s (size: %llu) - %s",
                         sym.name.c_str(), sym.size, filename.c_str());
            }
            else
            {
                snprintf(comment, sizeof(comment), "Symbol: %s - %s",
                         sym.name.c_str(), filename.c_str());
            }

            if (DbgSetCommentAt(sym.address, comment))
            {
                commentCount++;
            }
        }
    }

    // Second pass: Create functions with validation
    for (const auto &sym : loadedSymbols)
    {
        if (sym.isFunction && sym.size > 0)
        {
            duint startAddr = sym.address;
            duint endAddr = sym.endAddress;

            // Verify memory is accessible
            MEMORY_BASIC_INFORMATION mbi = {0};
            if (VirtualQuery((LPCVOID)startAddr, &mbi, sizeof(mbi)))
            {
                bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                bool isCommitted = (mbi.State == MEM_COMMIT);

                if (isCommitted && isExecutable)
                {
                    // Try to delete existing function first
                    DbgFunctionDel(startAddr);

                    // Create new function
                    if (DbgFunctionAdd(startAddr, endAddr))
                    {
                        functionCount++;
                        DPRINTF("Created function: %s at 0x%llX-0x%llX",
                                sym.name.c_str(), startAddr, endAddr);
                    }
                    else
                    {
                        DPRINTF("Failed to create function: %s at 0x%llX-0x%llX",
                                sym.name.c_str(), startAddr, endAddr);

                        // Try with manual analysis
                        DbgCmdExecDirect("anal");
                        Sleep(100); // Give time for analysis

                        if (DbgFunctionAdd(startAddr, endAddr))
                        {
                            functionCount++;
                            DPRINTF("Created function after analysis: %s", sym.name.c_str());
                        }
                    }
                }
                else
                {
                    DPRINTF("Skipped function %s: memory not executable (Protect: 0x%X, State: 0x%X)",
                            sym.name.c_str(), mbi.Protect, mbi.State);
                }
            }
            else
            {
                DPRINTF("Skipped function %s: cannot query memory at 0x%llX",
                        sym.name.c_str(), startAddr);
            }
        }
    }

    // Force UI refresh
    GuiUpdateAllViews();

    // Show summary
    char msg[1024];
    snprintf(msg, sizeof(msg),
             "DWARF Symbols Loaded Successfully!\n\n"
             "Labels set: %d/%zu\n"
             "Functions created: %d\n"
             "Comments added: %d\n\n"
             "Check the following tabs:\n"
             "• Functions tab for loaded functions\n"
             "• Symbols tab for all symbols\n"
             "• Memory view for comments and labels",
             labelCount, loadedSymbols.size(), functionCount, commentCount);

    MessageBoxA(NULL, msg, PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);

    DPRINTF("LoadSymbols completed: %d labels, %d functions, %d comments",
            labelCount, functionCount, commentCount);
}

// Helper function to select file using IFileOpenDialog and load symbols
bool LoadSymbolsFromFile()
{
    DPUTS("Entering LoadSymbolsFromFile");

    // Initialize COM
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr))
    {
        DPRINTF("CoInitialize failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to initialize COM.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    // Create IFileOpenDialog
    IFileOpenDialog *pFileOpen = NULL;
    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileOpen));
    if (FAILED(hr))
    {
        DPRINTF("CoCreateInstance failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to create file open dialog.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        CoUninitialize();
        return false;
    }

    // Set file filter
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

    // Set default extension
    hr = pFileOpen->SetDefaultExtension(L"exe");
    if (FAILED(hr))
    {
        DPRINTF("SetDefaultExtension failed, HRESULT=0x%X", hr);
    }

    // Get module base and path
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

    // Show the dialog
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

    // Get the selected file
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

            // Parse DWARF symbols
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
        MessageBoxA(NULL, "DWARFHelper Plugin v1.0 \nLoad DWARF symbols as labels\n By CynicRus", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
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
