#include <windows.h>
#include <Psapi.h>
#include <ShObjIdl.h>
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
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
//#define DEBUG
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
//static int menuHandleLabelsProcessMemory;
static int menuHandleAbout;

// Menu entry IDs
enum MenuAction {
    MA_LABELS_DWARF = 1001,
    //MA_LABELS_PROCESS_MEMORY = 1002,
    MA_ABOUT = 1004
};

// Structure to hold symbol information
struct Symbol {
    std::string name;
    duint address;  
    bool isFunction;
    duint size;
};

// Structure to hold line information
struct LineInfo {
    std::string file;
    unsigned int line;
    duint address;  
};

struct AddressCache {
    std::unordered_map<duint, duint> dwarfToRuntime;  
    duint imageBase;
    duint runtimeBase;
    duint baseOffset;
    
    void Initialize(duint dwarf_base, duint runtime_base) {
        imageBase = dwarf_base;
        runtimeBase = runtime_base;
        baseOffset = runtime_base - dwarf_base;
        dwarfToRuntime.clear();
        DPRINTF("Address cache initialized: DWARF base=0x%llX, Runtime base=0x%llX, Offset=0x%llX", 
                dwarf_base, runtime_base, baseOffset);
    }
    
    duint TranslateAddress(duint dwarf_addr) {
        auto it = dwarfToRuntime.find(dwarf_addr);
        if (it != dwarfToRuntime.end()) {
            return it->second;
        }
        
        duint runtime_addr = dwarf_addr + baseOffset;
        dwarfToRuntime[dwarf_addr] = runtime_addr;
        return runtime_addr;
    }
};

static AddressCache g_addressCache;

// Get base address from the PE
duint GetImageBaseFromHeaders(const void* imageData, size_t imageSize) {
    if (!imageData || imageSize < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    
    const IMAGE_DOS_HEADER* dosHeader = static_cast<const IMAGE_DOS_HEADER*>(imageData);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DPUTS("Invalid DOS signature");
        return 0;
    }
    
    if (dosHeader->e_lfanew >= imageSize || dosHeader->e_lfanew < 0) {
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

// Validate address within module bounds
static bool IsValidModuleAddress(duint address, duint modBase, duint modSize) {
    return address >= modBase && address < modBase + modSize;
}

// Utility to clean symbol names for x64dbg compatibility
static std::string CleanSymbolName(const std::string& name) {
    std::string cleaned = name;
    // Replace invalid characters (e.g., '$', ':') with '_'
    for (char& c : cleaned) {
        if (c == '$' || c == ':' || c == '@' || (!std::isalnum(c) && c != '_')) {
            c = '_';
        }
    }
    // Remove leading/trailing underscores
    while (!cleaned.empty() && cleaned.front() == '_') {
        cleaned.erase(cleaned.begin());
    }
    while (!cleaned.empty() && cleaned.back() == '_') {
        cleaned.pop_back();
    }
    return cleaned.empty() ? "Symbol" : cleaned;
}

// Get current EIP/RIP
duint GetCurrentEIP() {
    DPUTS("Entering GetCurrentEIP");
    REGDUMP registers;
    if (!DbgIsDebugging()) {
        DPUTS("DbgIsDebugging returned false");
        return 0;
    }
    if (DbgGetRegDumpEx(&registers, sizeof(REGDUMP))) {
        DPRINTF("DbgGetRegDumpEx succeeded, cip = 0x%llX", registers.regcontext.cip);
        if (registers.regcontext.cip == 0) {
            DPUTS("Warning: cip is 0, invalid instruction pointer");
        }
        return registers.regcontext.cip;
    }
    DPUTS("DbgGetRegDumpEx failed");
    return 0;
}

// Parse DWARF line information from file
static std::vector<LineInfo> ParseDWARFLineInfo(Dwarf_Debug dbg, duint dwarfImageBase, duint runtimeBase, duint modSize) {
    DPUTS("Entering ParseDWARFLineInfo");
    std::vector<LineInfo> lineInfos;

    if (!dbg) {
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
                                  &typeoffset, &next_cu_header, &header_cu_type, &error) == DW_DLV_OK) {
        Dwarf_Die cu_die = 0;
        if (dwarf_siblingof_b(dbg, 0, is_info, &cu_die, &error) != DW_DLV_OK) {
            DPUTS("Failed to get CU DIE for line info");
            dwarf_dealloc_error(dbg, error);
            continue;
        }

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
                            duint adjusted_addr;
                            if (dwarfImageBase != 0) {
                                adjusted_addr = (static_cast<duint>(lineaddr) - dwarfImageBase) + runtimeBase;
                            } else {
                                adjusted_addr = static_cast<duint>(lineaddr) + runtimeBase;
                            }
                            
                            if (modSize == 0 || IsValidModuleAddress(adjusted_addr, runtimeBase, modSize)) {
                                lineInfos.push_back({ std::string(filename), static_cast<unsigned int>(lineno), adjusted_addr });
                                DPRINTF("Line info: %s:%u at DWARF addr 0x%llX -> runtime addr 0x%llX", 
                                        filename, lineno, lineaddr, adjusted_addr);
                            } else {
                                DPRINTF("Skipped line info: %s:%u, invalid address 0x%llX", filename, lineno, adjusted_addr);
                            }
                        }
                        if (filename) {
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

// Parse DWARF symbols from file
std::vector<Symbol> ParseDWARFFile(const std::filesystem::path& path, duint runtimeBase) {
    try {
        DPUTS("Entering ParseDWARFFile");
        DPRINTF("File path: %s, runtimeBase: 0x%llX", path.string().c_str(), runtimeBase);
        std::vector<Symbol> loadedSymbols;

        // Get module size for validation
        MODULEINFO modInfo = { 0 };
        duint modSize = 0;
        if (runtimeBase) {
            HANDLE hProcess = GetCurrentProcess();
            if (GetModuleInformation(hProcess, (HMODULE)runtimeBase, &modInfo, sizeof(MODULEINFO))) {
                modSize = modInfo.SizeOfImage;
                DPRINTF("Runtime base: 0x%llX, size: 0x%llX", runtimeBase, modSize);
            } else {
                DPUTS("GetModuleInformation failed");
            }
        }

        Dwarf_Debug dbg = 0;
        Dwarf_Error error = 0;
        HANDLE hFile = CreateFileA(path.string().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DPUTS("Failed to open file with CreateFileA");
            MessageBoxA(NULL, "Failed to open file containing DWARF debug info.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            return loadedSymbols;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            DPUTS("Failed to get file size");
            CloseHandle(hFile);
            return loadedSymbols;
        }

        std::vector<char> fileData(fileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
            DPUTS("Failed to read file data");
            CloseHandle(hFile);
            return loadedSymbols;
        }
        CloseHandle(hFile);

        // Get image base from the PE headers
        duint dwarfImageBase = GetImageBaseFromHeaders(fileData.data(), fileSize);
        DPRINTF("DWARF image base from headers: 0x%llX", dwarfImageBase);
        
        g_addressCache.Initialize(dwarfImageBase, runtimeBase);

        int res = dwarf_init_path_a(path.string().c_str(), NULL, 0, DW_GROUPNUMBER_ANY, 0, NULL, NULL, &dbg, &error);
        if (res != DW_DLV_OK) {
            DPRINTF("dwarf_init_path_a failed, res=%d, error=%s", res, dwarf_errmsg(error));
            MessageBoxA(NULL, "Failed to initialize DWARF debug info.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            if (error) dwarf_dealloc_error(dbg, error);
            return loadedSymbols;
        }

        if (!dbg) {
            DPUTS("dwarf_init_path_a returned null Dwarf_Debug");
            MessageBoxA(NULL, "Failed to initialize DWARF debug context.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
            return loadedSymbols;
        }

        // Set address size and frame rules
        dwarf_set_default_address_size(dbg, sizeof(duint));
        dwarf_set_frame_rule_initial_value(dbg, DW_FRAME_UNDEFINED_VAL);
        dwarf_set_harmless_error_list_size(dbg, 50);

        // Iterate through DWARF compilation units
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
            if (dwarf_siblingof_b(dbg, 0, is_info, &cu_die, &error) != DW_DLV_OK) {
                DPUTS("Failed to get CU DIE");
                if (error) dwarf_dealloc_error(dbg, error);
                continue;
            }

            // Iterate through DIEs
            Dwarf_Die child_die = 0;
            if (dwarf_child(cu_die, &child_die, &error) == DW_DLV_OK) {
                do {
                    Dwarf_Half tag = 0;
                    if (dwarf_tag(child_die, &tag, &error) != DW_DLV_OK) {
                        if (error) dwarf_dealloc_error(dbg, error);
                        continue;
                    }

                    if (tag == DW_TAG_subprogram || tag == DW_TAG_variable || tag == DW_TAG_label) {
                        char* name = 0;
                        if (dwarf_diename(child_die, &name, &error) == DW_DLV_OK && name) {
                            Dwarf_Addr low_pc = 0;
                            Dwarf_Attribute attr = 0;
                            if (dwarf_attr(child_die, DW_AT_low_pc, &attr, &error) == DW_DLV_OK) {
                                Dwarf_Half attr_form = 0;
                                if (dwarf_whatform(attr, &attr_form, &error) == DW_DLV_OK &&
                                    attr_form == DW_FORM_addr) {
                                    if (dwarf_formaddr(attr, &low_pc, &error) == DW_DLV_OK && low_pc != 0) {
                                        duint adjusted_addr = g_addressCache.TranslateAddress(static_cast<duint>(low_pc));
                                        
                                        if (modSize == 0 || IsValidModuleAddress(adjusted_addr, runtimeBase, modSize)) {
                                            std::string cleaned_name = CleanSymbolName(name);
                                            
                                            duint symbolSize = 0;
                                            Dwarf_Attribute size_attr = 0;
                                            if (dwarf_attr(child_die, DW_AT_byte_size, &size_attr, &error) == DW_DLV_OK) {
                                                Dwarf_Unsigned size_val = 0;
                                                if (dwarf_formudata(size_attr, &size_val, &error) == DW_DLV_OK) {
                                                    symbolSize = static_cast<duint>(size_val);
                                                }
                                                dwarf_dealloc_attribute(size_attr);
                                            }
                                            
                                            loadedSymbols.push_back({ 
                                                cleaned_name, 
                                                adjusted_addr, 
                                                tag == DW_TAG_subprogram,
                                                symbolSize 
                                            });
                                            DPRINTF("Added symbol: %s at DWARF addr 0x%llX -> runtime addr 0x%llX (size: %llu)", 
                                                    cleaned_name.c_str(), low_pc, adjusted_addr, symbolSize);
                                        } else {
                                            DPRINTF("Skipped symbol: %s, invalid address 0x%llX (outside module range)", 
                                                    name, adjusted_addr);
                                        }
                                    }
                                }
                                dwarf_dealloc_attribute(attr);
                            }
                            dwarf_dealloc(dbg, name, DW_DLA_STRING);
                        }
                    }

                    Dwarf_Die next_die = 0;
                    int sib_res = dwarf_siblingof_b(dbg, child_die, is_info, &next_die, &error);
                    dwarf_dealloc_die(child_die);
                    child_die = next_die;
                    if (sib_res != DW_DLV_OK) {
                        if (error) dwarf_dealloc_error(dbg, error);
                        break;
                    }
                } while (child_die);
            }
            dwarf_dealloc_die(cu_die);
        }

        // Parse line information
        auto lineInfos = ParseDWARFLineInfo(dbg, dwarfImageBase, runtimeBase, modSize);
        for (const auto& line : lineInfos) {
            char comment[256];
            snprintf(comment, sizeof(comment), "%s:%u", line.file.c_str(), line.line);
            if (DbgSetCommentAt(line.address, comment)) {
                DPRINTF("Set comment: %s at 0x%llX", comment, line.address);
            } else {
                DPRINTF("Failed to set comment: %s at 0x%llX", comment, line.address);
            }
        }

        dwarf_finish(dbg);
        DPRINTF("ParseDWARFFile: Loaded %zu symbols", loadedSymbols.size());
        if (loadedSymbols.empty()) {
            DPUTS("No symbols loaded from file");
            MessageBoxA(NULL, "No symbols were loaded from the file. Check if it contains valid DWARF debug info.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        }
        return loadedSymbols;
    } catch (...) {
        DPUTS("Exception in ParseDWARFFile");
        MessageBoxA(NULL, "An error occurred while parsing DWARF file.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return std::vector<Symbol>();
    }
}


void LoadSymbols(duint runtimeBase, const std::vector<Symbol>& loadedSymbols) {
    DPUTS("Entering LoadSymbols");
    DPRINTF("Runtime base: 0x%llX, Symbols count: %zu", runtimeBase, loadedSymbols.size());
    if (loadedSymbols.empty()) {
        DPUTS("No symbols to load");
        MessageBoxA(NULL, "No symbols to load.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        return;
    }

    int successCount = 0;
    for (const auto& sym : loadedSymbols) {
        // Address already corrected in ParseDWARFFile
        duint address = sym.address;
        bool success = DbgSetLabelAt(address, sym.name.c_str());
        
        // Create function in the debugger
        if (success && sym.isFunction && sym.size > 0) {
            DbgFunctionAdd(address, address + sym.size);
            DPRINTF("Created function: %s at 0x%llX (size: %llu)", sym.name.c_str(), address, sym.size);
        }
        
        DPRINTF("Setting label: %s at 0x%llX, Success: %d", sym.name.c_str(), address, success);
        if (success) {
            successCount++;
        } else {
            DPRINTF("Failed to set label %s at 0x%llX", sym.name.c_str(), address);
        }
    }

    DPRINTF("Successfully set %d/%zu labels", successCount, loadedSymbols.size());
    if (successCount > 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Successfully loaded %d/%zu symbols", successCount, loadedSymbols.size());
        MessageBoxA(NULL, msg, PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxA(NULL, "No labels were set. Check the module base address and DWARF data.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
    }
}

// Helper function to select file using IFileOpenDialog and load symbols
bool LoadSymbolsFromFile() {
    DPUTS("Entering LoadSymbolsFromFile");

    // Initialize COM
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        DPRINTF("CoInitialize failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to initialize COM.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    // Create IFileOpenDialog
    IFileOpenDialog* pFileOpen = NULL;
    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileOpen));
    if (FAILED(hr)) {
        DPRINTF("CoCreateInstance failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to create file open dialog.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        CoUninitialize();
        return false;
    }

    // Set file filter
    COMDLG_FILTERSPEC fileTypes[] = {
        { L"Executable Files (*.exe;*.dll;*.elf)", L"*.exe;*.dll;*.elf" },
        { L"All Files (*.*)", L"*.*" }
    };
    hr = pFileOpen->SetFileTypes(2, fileTypes);
    if (FAILED(hr)) {
        DPRINTF("SetFileTypes failed, HRESULT=0x%X", hr);
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    // Set default extension
    hr = pFileOpen->SetDefaultExtension(L"exe");
    if (FAILED(hr)) {
        DPRINTF("SetDefaultExtension failed, HRESULT=0x%X", hr);
    }

    // Get module base and path
    duint runtimeBase = 0;
    char moduleName[MAX_PATH] = "";
    duint currentEIP = GetCurrentEIP();
    auto* dbgFuncs = DbgFunctions();
    DPRINTF("DbgFunctions() returned 0x%p", dbgFuncs);
    if (!dbgFuncs) {
        DPUTS("DbgFunctions() returned nullptr");
        pFileOpen->Release();
        CoUninitialize();
        MessageBoxA(NULL, "Failed to get DbgFunctions. SDK may be incompatible.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    if (currentEIP) {
        if (DbgGetModuleAt(currentEIP, moduleName)) {
            DPRINTF("DbgGetModuleAt succeeded, module name: %s", moduleName);
            runtimeBase = dbgFuncs->ModBaseFromName(moduleName);
            DPRINTF("DbgFunctions()->ModBaseFromName returned 0x%llX", runtimeBase);
        } else {
            DPUTS("DbgGetModuleAt failed");
        }
    } else {
        DPUTS("Warning: cip is 0, invalid instruction pointer");
    }

    if (!runtimeBase) {
        DPUTS("No process to add DWARF info");
        MessageBoxA(NULL, "No process is being debugged. Please start debugging a process first.", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    char modulePath[MAX_PATH] = "";
    char initialDir[MAX_PATH] = "";
    if (dbgFuncs->ModPathFromAddr(runtimeBase, modulePath, MAX_PATH)) {
        DPRINTF("Module path: %s", modulePath);
        strncpy_s(initialDir, modulePath, MAX_PATH);
        char* lastSlash = strrchr(initialDir, '\\');
        if (lastSlash) *lastSlash = '\0';
        DPRINTF("Initial directory: %s", initialDir);
        std::wstring wInitialDir = std::wstring(initialDir, initialDir + strlen(initialDir));
        IShellItem* pFolder = NULL;
        if (SUCCEEDED(SHCreateItemFromParsingName(wInitialDir.c_str(), NULL, IID_PPV_ARGS(&pFolder)))) {
            pFileOpen->SetFolder(pFolder);
            pFolder->Release();
        }
    }

    // Show the dialog
    HWND hwnd = GuiGetWindowHandle();
    DPRINTF("Opening file dialog, GuiGetWindowHandle=0x%p, IsWindow(GuiGetWindowHandle)=%d", hwnd, IsWindow(hwnd));
    hr = pFileOpen->Show(hwnd && IsWindow(hwnd) ? hwnd : NULL);
    if (FAILED(hr)) {
        DPRINTF("IFileOpenDialog::Show failed, HRESULT=0x%X", hr);
        DPUTS("No file selected");
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    // Get the selected file
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

            // Parse DWARF symbols
            auto loadedSymbols = ParseDWARFFile(filePath, runtimeBase);
            if (!loadedSymbols.empty()) {
                DPRINTF("Loaded %zu symbols", loadedSymbols.size());
                LoadSymbols(runtimeBase, loadedSymbols);
            } else {
                DPUTS("Failed to parse DWARF debug info");
            }
        } else {
            DPRINTF("GetDisplayName failed, HRESULT=0x%X", hr);
        }
        pItem->Release();
    } else {
        DPRINTF("GetResult failed, HRESULT=0x%X", hr);
        DPUTS("No file selected");
    }

    pFileOpen->Release();
    CoUninitialize();
    return true;
}

// Menu callback
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info) {
    DPRINTF("CBMENUENTRY called with cbType=%d, hEntry=%d", cbType, info ? info->hEntry : -1);
    if (cbType != CB_MENUENTRY || !info) {
        DPUTS("Invalid cbType or menu entry info");
        return;
    }

    switch (info->hEntry) {
    case MA_LABELS_DWARF:
        DPUTS("Selected: Load DWARF Symbols from File");
        if (!DbgIsDebugging()) {
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
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    DPUTS("pluginit called");
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, sizeof(initStruct->pluginName));
    pluginHandle = initStruct->pluginHandle;
    DPRINTF("Plugin initialized: handle=%d, version=%d, sdkVersion=%d", pluginHandle, PLUGIN_VERSION, PLUG_SDKVERSION);
    return true;
}

// Plugin setup
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    hwndDlg = setupStruct->hwndDlg;
    menuHandleLabelsDWARF = _plugin_menuaddentry(setupStruct->hMenu, MA_LABELS_DWARF, "Load DWARF Symbols from File");
    menuHandleAbout = _plugin_menuaddentry(setupStruct->hMenu, MA_ABOUT, "About");
}

// Plugin cleanup
PLUG_EXPORT bool plugstop() {
    _plugin_menuclear(pluginHandle);
    return true;
}

// DLL entry point
BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE hinstDLL, [[maybe_unused]] DWORD fdwReason, [[maybe_unused]] LPVOID lpvReserved) {
    return TRUE;
}