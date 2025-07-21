# DWARFHelper Plugin

## Overview
DWARFHelper is a plugin for x64dbg, designed to load DWARF debug symbols from executable files (e.g., `.exe`, `.dll`) and apply them as labels and function information within the debugger. It supports both 32-bit and 64-bit architectures and integrates with the x64dbg plugin system to enhance debugging capabilities by parsing DWARF debug information.

## Features
- **Load DWARF Symbols**: Extracts symbols (functions, variables, labels) from DWARF debug information in executable files and sets them as labels in x64dbg.
- **Line Information**: Parses DWARF line information to set comments with file and line number details at corresponding addresses.
- **Address Translation**: Handles address translation between DWARF image base and runtime base using a caching mechanism.
- **File Selection**: Uses a file open dialog to select executable files containing DWARF debug info.
- **Error Handling**: Provides detailed debug logging and user feedback through message boxes for errors or warnings.
- **Menu Integration**: Adds menu entries to x64dbg for loading DWARF symbols and displaying an about dialog.

## Dependencies
- **Libdwarf**: Required for parsing DWARF debug information.
- **x64dbg SDK**: Required for plugin functionality and integration with x64dbg.
- **Windows API**: For file handling and dialog interfaces.

These libraries must be available in the appropriate architecture (x86 or x64) as specified in the code.

## Build Instructions
To build the DWARFHelper plugin, follow these steps:

1. **Install Dependencies**:
   - Ensure `Libdwarf` is installed and available in your build environment.
   - Install MinGW for compiling on Windows.
   - Ensure the x64dbg SDK  are available in the correct architecture (x86 or x64).

2. **Configure the Build**:
   ```bash
   cmake -G "MinGW Makefiles" ..
   ```

3. **Compile the Plugin**:
   ```bash
   mingw32-make
   ```

4. **Output**:
   - The compiled plugin DLL will be generated (e.g., `DWARFHelper.dp64` for x64 or `DWARFHelper.dp32` x86).
   - Place the DLL in the x64dbg plugins directory.

## Installation
1. Copy the compiled `DWARFHelper.dp64/32` to the x64dbg plugins directory (e.g., `x64dbg\release\x32\plugins` or `x64dbg\release\x64\plugins`).
2. Launch x64dbg, and the plugin will automatically load.
3. Access the plugin via the Plugins menu in x64dbg, where you can select "Load DWARF Symbols from File" or "About".

## Usage
1. **Start Debugging**: Open a process in x64dbg to enable the plugin functionality. Pause the process at a valid instruction pointer (EIP/RIP) for your main module.
                        The plugin locates module base relative to the current EIP/RIP, so this step is required.


2. **Load DWARF Symbols**:
   - Go to the Plugins menu and select "Load DWARF Symbols from File".
   - A file dialog will open, allowing you to select an executable file (`.exe`, `.dll`) containing DWARF debug information.
   - The plugin will parse the DWARF data, translate addresses, and apply symbols as labels and functions in x64dbg.
3. **View Results**:
   - Symbols are set as labels at their runtime addresses.
   - Line information is added as comments in the format `file:line`.
   - Functions are marked with their start and end addresses.
4. **About Dialog**: Select "About" from the Plugins menu to view plugin information.

## Code Structure
- **Header Inclusions**:
  - Windows API headers for file and dialog handling.
  - Libdwarf for DWARF parsing.
  - x64dbg SDK headers for debugger integration.
  - Additional libraries for utility functions.
- **Key Structures**:
  - `Symbol`: Holds symbol name, address, type (function or not), and size.
  - `LineInfo`: Stores file, line number, and address for line information.
  - `AddressCache`: Manages address translation between DWARF and runtime bases.
- **Main Functions**:
  - `GetImageBaseFromHeaders`: Extracts the image base from PE headers.
  - `CleanSymbolName`: Sanitizes symbol names for x64dbg compatibility.
  - `GetCurrentEIP`: Retrieves the current instruction pointer.
  - `ParseDWARFLineInfo`: Parses DWARF line information and adjusts addresses.
  - `ParseDWARFFile`: Extracts symbols from a DWARF file and applies address translation.
  - `LoadSymbols`: Sets labels and functions in x64dbg based on parsed symbols.
  - `LoadSymbolsFromFile`: Handles file selection and initiates DWARF parsing.
  - `CBMENUENTRY`: Handles plugin menu interactions.
  - `pluginit`, `plugsetup`, `plugstop`: Standard x64dbg plugin lifecycle functions.

## Debugging
- Debug logging is enabled when the `DEBUG` macro is defined.
- Logs are output using `_plugin_logprintf` with the prefix `[DWARFHelper]`.
- Use `DPRINTF` for formatted debug messages and `DPUTS` for simple string messages.

## License
This project is licensed under the MIT License.

```text
MIT License

Copyright (c) 2025 Aleksandr Vorobev aka CynicRus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Credits
- Based on FASMDbgHelper by CynicRus.
- Developed for integration with x64dbg.

## Contributing
Contributions are welcome! Please submit issues or pull requests to the GitHub repository.
```
