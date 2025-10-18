cmake_minimum_required(VERSION 3.16)
project(TigerFoxHybrid VERSION 1.0.0 LANGUAGES CXX)

# C++ Configuration
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags for performance
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -DNDEBUG -flto -mavx2")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -ggdb -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")

# Additional optimizations for Release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -ffast-math
        -funroll-loops
        -fprefetch-loop-arrays
        -mavx2
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

# Source files for ORIGINAL version
set(ORIGINAL_SOURCES
    src/main.cpp
    src/tiger_system.cpp
    src/utils.cpp
    src/engine/rule_engine.cpp
    src/engine/fast_sequential_engine.cpp
    src/engine/successive_engine.cpp
    src/engine/optimized_parallel_engine.cpp
    src/handlers/packet_handler.cpp
    src/loaders/rule_loader.cpp
)

# Headers
include_directories(src)

# Executable: ORIGINAL (multi-worker with TCP reassembly)
add_executable(tiger-fox ${ORIGINAL_SOURCES})

# ============================================================
# TIGER-FOX (ORIGINAL - Multi-worker)
# ============================================================
target_compile_definitions(tiger-fox PRIVATE
    PCRE2_CODE_UNIT_WIDTH=8
    TIGER_FOX_VERSION_MAJOR=1
    TIGER_FOX_VERSION_MINOR=0
    TIGER_FOX_VERSION_PATCH=0
    $<$<CONFIG:Debug>:TIGER_FOX_DEBUG>
    $<$<CONFIG:Release>:TIGER_FOX_RELEASE>
)

target_link_libraries(tiger-fox 
    ${NETFILTER_QUEUE_LIBRARIES}
    ${PCRE2_LIBRARIES}
    Threads::Threads
    pthread
)

if(nlohmann_json_FOUND)
    target_link_libraries(tiger-fox nlohmann_json::nlohmann_json)
else()
    target_include_directories(tiger-fox PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
endif()

target_include_directories(tiger-fox PRIVATE 
    ${NETFILTER_QUEUE_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
)

target_compile_options(tiger-fox PRIVATE
    ${NETFILTER_QUEUE_CFLAGS_OTHER}
    ${PCRE2_CFLAGS_OTHER}
)

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
message(STATUS "  Threads: Available")
message(STATUS "==================================================")
