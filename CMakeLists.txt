cmake_minimum_required(VERSION 3.16)
project(TigerFoxHybrid VERSION 1.0.0 LANGUAGES CXX)

# C++ Configuration
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags for performance
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -DNDEBUG -flto")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -ggdb -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")

# Additional optimizations for Release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -ffast-math
        -funroll-loops
        -fprefetch-loop-arrays
    )
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)

# NetFilter Queue
pkg_check_modules(NETFILTER_QUEUE REQUIRED libnetfilter_queue)
if(NOT NETFILTER_QUEUE_FOUND)
    message(FATAL_ERROR "libnetfilter_queue not found. Install with: sudo apt install libnetfilter-queue-dev")
endif()

# nlohmann JSON
find_package(nlohmann_json 3.2.0 QUIET)
if(NOT nlohmann_json_FOUND)
    find_path(NLOHMANN_JSON_INCLUDE_DIR
        NAMES nlohmann/json.hpp
        PATHS /usr/include /usr/local/include
    )
    if(NOT NLOHMANN_JSON_INCLUDE_DIR)
        message(FATAL_ERROR "nlohmann/json not found. Install with: sudo apt install nlohmann-json3-dev")
    endif()
endif()

# Threads
find_package(Threads REQUIRED)

# PCRE2
pkg_check_modules(PCRE2 REQUIRED libpcre2-8)
if(NOT PCRE2_FOUND)
    message(FATAL_ERROR "libpcre2 not found. Install with: sudo apt install libpcre2-dev")
endif()

# llhttp (ultra-rapide pour HTTP parsing, 10-20x plus rapide)
find_library(LLHTTP_LIBRARY NAMES llhttp libllhttp)
find_path(LLHTTP_INCLUDE_DIR NAMES llhttp.h PATHS /usr/include /usr/local/include)
if(NOT LLHTTP_LIBRARY OR NOT LLHTTP_INCLUDE_DIR)
    message(FATAL_ERROR "llhttp not found. Install with: sudo apt install libllhttp-dev")
endif()

# Hyperscan (100x plus rapide que PCRE2 pour regex matching)
find_library(HYPERSCAN_LIBRARY NAMES hs libhs)
find_path(HYPERSCAN_INCLUDE_DIR NAMES hs/hs.h PATHS /usr/include /usr/local/include)
if(NOT HYPERSCAN_LIBRARY OR NOT HYPERSCAN_INCLUDE_DIR)
    message(WARNING "Hyperscan not found. Performance will be degraded. Install with: sudo apt install libhyperscan-dev")
endif()

# nDPI (protocol detection)
pkg_check_modules(NDPI libndpi)
if(NOT NDPI_FOUND)
    message(WARNING "nDPI not found. Protocol detection will be limited. Install with: sudo apt install libndpi-dev")
endif()

# Source files
file(GLOB_RECURSE SOURCES 
    src/*.cpp
    src/engine/*.cpp
    src/handlers/*.cpp
    src/loaders/*.cpp
)

# Headers
include_directories(src)

# Executable
add_executable(tiger-fox ${SOURCES})

# Preprocessor definitions
target_compile_definitions(tiger-fox PRIVATE
    PCRE2_CODE_UNIT_WIDTH=8
    TIGER_FOX_VERSION_MAJOR=1
    TIGER_FOX_VERSION_MINOR=0
    TIGER_FOX_VERSION_PATCH=0
    $<$<CONFIG:Debug>:TIGER_FOX_DEBUG>
    $<$<CONFIG:Release>:TIGER_FOX_RELEASE>
)

# Link libraries
target_link_libraries(tiger-fox 
    ${NETFILTER_QUEUE_LIBRARIES}
    ${PCRE2_LIBRARIES}
    ${LLHTTP_LIBRARY}
    Threads::Threads
    pthread
)

# Link Hyperscan if available
if(HYPERSCAN_LIBRARY)
    target_link_libraries(tiger-fox ${HYPERSCAN_LIBRARY})
    target_compile_definitions(tiger-fox PRIVATE HAVE_HYPERSCAN=1)
endif()

# Link nDPI if available
if(NDPI_FOUND)
    target_link_libraries(tiger-fox ${NDPI_LIBRARIES})
    target_compile_definitions(tiger-fox PRIVATE HAVE_NDPI=1)
endif()

# nlohmann-json linking
if(nlohmann_json_FOUND)
    target_link_libraries(tiger-fox nlohmann_json::nlohmann_json)
else()
    target_include_directories(tiger-fox PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
endif()

# Include directories
target_include_directories(tiger-fox PRIVATE 
    ${NETFILTER_QUEUE_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
    ${LLHTTP_INCLUDE_DIR}
)

# Include Hyperscan if available
if(HYPERSCAN_INCLUDE_DIR)
    target_include_directories(tiger-fox PRIVATE ${HYPERSCAN_INCLUDE_DIR})
endif()

# Include nDPI if available
if(NDPI_FOUND)
    target_include_directories(tiger-fox PRIVATE ${NDPI_INCLUDE_DIRS})
endif()

# Compile options
target_compile_options(tiger-fox PRIVATE
    ${NETFILTER_QUEUE_CFLAGS_OTHER}
    ${PCRE2_CFLAGS_OTHER}
)

# Linker options for Release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(tiger-fox PRIVATE
        -flto
        -Wl,--gc-sections
    )
endif()

# Installation
install(TARGETS tiger-fox DESTINATION bin)
install(DIRECTORY rules/ DESTINATION share/tiger-fox/rules)

# Build info
message(STATUS "==================================================")
message(STATUS "Tiger-Fox C++ Hybrid Network Filtering System")
message(STATUS "==================================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  NetFilter Queue: ${NETFILTER_QUEUE_VERSION}")
message(STATUS "  PCRE2: ${PCRE2_VERSION}")
message(STATUS "  llhttp: ${LLHTTP_LIBRARY}")
if(HYPERSCAN_LIBRARY)
    message(STATUS "  Hyperscan: ${HYPERSCAN_LIBRARY} (100x faster regex)")
else()
    message(STATUS "  Hyperscan: NOT FOUND (performance will be degraded)")
endif()
if(NDPI_FOUND)
    message(STATUS "  nDPI: ${NDPI_VERSION} (protocol detection)")
else()
    message(STATUS "  nDPI: NOT FOUND (limited protocol detection)")
endif()
message(STATUS "  Threads: Available")
message(STATUS "==================================================")
