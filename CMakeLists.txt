cmake_minimum_required(VERSION 3.15)
project(DWARFDbgHelper LANGUAGES CXX)

# Установка стандарта C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Определение корневой папки x64dbg
set(X64DBG_ROOT "C:/Reversing/x64dbg/" CACHE PATH "Path to x64dbg root directory")

# Поиск libdwarf
find_path(LIBDWARF_INCLUDE_DIR 
    NAMES libdwarf.h
    PATHS C:/mingw64/include
    PATH_SUFFIXES libdwarf
)

find_library(LIBDWARF_LIBRARY
    NAMES dwarf libdwarf
    PATHS C:/mingw64/lib
    PATH_SUFFIXES lib
)

if(NOT LIBDWARF_INCLUDE_DIR OR NOT LIBDWARF_LIBRARY)
    message(FATAL_ERROR "libdwarf not found. Please install libdwarf first.")
endif()

message(STATUS "Found libdwarf: ${LIBDWARF_LIBRARY}")
message(STATUS "Found libdwarf headers: ${LIBDWARF_INCLUDE_DIR}")
message(STATUS "X64DBG_ROOT: ${X64DBG_ROOT}")
message(STATUS "Looking for bridgemain.h in: ${X64DBG_ROOT}/pluginsdk")

# Проверка существования файлов
if(EXISTS "${X64DBG_ROOT}/pluginsdk/bridgemain.h")
    message(STATUS "bridgemain.h found!")
else()
    message(FATAL_ERROR "bridgemain.h NOT found in ${X64DBG_ROOT}/pluginsdk/")
endif()

if(EXISTS "${X64DBG_ROOT}/pluginsdk")
    message(STATUS "pluginsdk directory exists")
    file(GLOB SDK_HEADERS "${X64DBG_ROOT}/pluginsdk/*.h")
    message(STATUS "Headers in pluginsdk: ${SDK_HEADERS}")
else()
    message(FATAL_ERROR "pluginsdk directory does not exist!")
endif()

# Определение архитектуры сборки по размеру указателя
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "x64")
    set(PLUGIN_SUFFIX ".dp64")
    set(X64DBG_LIB_NAMES x64dbg x64bridge)
    set(THIRD_PARTY_LIB_NAMES DeviceNameResolver_x64 jansson_x64 lz4_x64 TitanEngine_x64 XEDParse_x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(ARCH "x86") 
    set(PLUGIN_SUFFIX ".dp32")
    set(X64DBG_LIB_NAMES x32dbg x32bridge)
    set(THIRD_PARTY_LIB_NAMES DeviceNameResolver_x86 jansson_x86 lz4_x86 TitanEngine_x86 XEDParse_x86)
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()


# Исходные файлы
set(SOURCES
    DWARFDbgHelper.cpp
)

# Путь к заголовкам x64dbg plugin SDK и libdwarf
include_directories("${X64DBG_ROOT}/pluginsdk" "${LIBDWARF_INCLUDE_DIR}")

# Создание плагина как разделяемой библиотеки
add_library(DWARFDbgHelper SHARED ${SOURCES})

# Настройка путей поиска библиотек для компоновщика
target_link_directories(DWARFDbgHelper PRIVATE 
    "${X64DBG_ROOT}/pluginsdk"
    "${X64DBG_ROOT}/pluginsdk/DeviceNameResolver" 
    "${X64DBG_ROOT}/pluginsdk/jansson" 
    "${X64DBG_ROOT}/pluginsdk/lz4" 
    "${X64DBG_ROOT}/pluginsdk/TitanEngine" 
    "${X64DBG_ROOT}/pluginsdk/XEDParse"
)

# Линковка с необходимыми библиотеками
target_link_libraries(DWARFDbgHelper PRIVATE 
    comdlg32 
    dwarf
    ${X64DBG_LIB_NAMES}
    ${THIRD_PARTY_LIB_NAMES}
)

# Установка имени и расширения для плагина
set_target_properties(DWARFDbgHelper PROPERTIES
    OUTPUT_NAME "DWARFDbgHelper"
    SUFFIX "${PLUGIN_SUFFIX}"
    PREFIX ""
)

# Установка флагов компиляции для MinGW
target_compile_options(DWARFDbgHelper PRIVATE 
    -Wall 
    -Wextra 
    -O2
    -DWINDOWS_IGNORE_PACKING_MISMATCH
    -static
)

target_compile_definitions(DWARFDbgHelper PRIVATE LIBDWARF_STATIC)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(DWARFDbgHelper PRIVATE DEBUG)
    target_compile_options(DWARFDbgHelper PRIVATE -g)
endif()

# Статическая линковка runtime библиотек для MinGW
target_link_options(DWARFDbgHelper PRIVATE -static
        -static-libgcc  
        -static-libstdc++
        -Wl,--whole-archive
        -lwinpthread
        -Wl,--no-whole-archive)