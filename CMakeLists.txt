cmake_minimum_required(VERSION 3.21)
project(FlowGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

set(NPCAP_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/npcap-sdk" CACHE PATH "Npcap SDK directory")
find_path(NPCAP_INCLUDE_DIR pcap.h PATHS "${NPCAP_SDK_DIR}/Include" NO_DEFAULT_PATH REQUIRED)
find_library(NPCAP_LIBRARY wpcap PATHS "${NPCAP_SDK_DIR}/Lib/x64" NO_DEFAULT_PATH REQUIRED)
add_library(Npcap::Npcap UNKNOWN IMPORTED)
set_target_properties(Npcap::Npcap PROPERTIES
    IMPORTED_LOCATION "${NPCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${NPCAP_INCLUDE_DIR}")

qt_add_executable(FlowGuard
    src/main.cpp
    src/ui/main_window.cpp
    src/ui/main_window.h
    src/core/packet_types.h)
target_include_directories(FlowGuard PRIVATE src)
target_link_libraries(FlowGuard PRIVATE Qt6::Widgets Npcap::Npcap ws2_32)
target_compile_definitions(FlowGuard PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MSVC)
    target_compile_options(FlowGuard PRIVATE /W4 /utf-8)
endif()

enable_testing()
add_test(NAME stage0_smoke COMMAND FlowGuard --smoke-test)
set_tests_properties(stage0_smoke PROPERTIES TIMEOUT 15)
