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

function(flowguard_configure_cpp target)
    target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8)
    endif()
endfunction()

add_library(flowguard_capture STATIC
    src/capture/device_enumerator.cpp
    src/capture/device_enumerator_detail.h
    src/core/module_contracts.h)
target_include_directories(flowguard_capture PUBLIC src)
target_link_libraries(flowguard_capture PUBLIC Npcap::Npcap ws2_32)
flowguard_configure_cpp(flowguard_capture)

add_executable(flowguard_capture_probe src/capture/capture_probe.cpp)
target_link_libraries(flowguard_capture_probe PRIVATE flowguard_capture)
flowguard_configure_cpp(flowguard_capture_probe)

add_library(flowguard_contracts_check OBJECT tests/module_contracts_compile.cpp)
target_include_directories(flowguard_contracts_check PRIVATE src)
flowguard_configure_cpp(flowguard_contracts_check)

add_executable(flowguard_capture_tests tests/device_enumerator_tests.cpp)
target_link_libraries(flowguard_capture_tests PRIVATE flowguard_capture)
flowguard_configure_cpp(flowguard_capture_tests)

set_target_properties(flowguard_capture flowguard_capture_probe
    flowguard_contracts_check flowguard_capture_tests PROPERTIES
    AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

qt_add_executable(FlowGuard
    src/main.cpp
    src/ui/main_window.cpp
    src/ui/main_window.h
    src/core/packet_types.h)
target_include_directories(FlowGuard PRIVATE src)
target_link_libraries(FlowGuard PRIVATE Qt6::Widgets flowguard_capture)
flowguard_configure_cpp(FlowGuard)

enable_testing()
add_test(NAME stage0_smoke COMMAND FlowGuard --smoke-test)
set_tests_properties(stage0_smoke PROPERTIES TIMEOUT 15)
add_test(NAME capture_device_enumerator COMMAND flowguard_capture_tests)
add_test(NAME capture_probe_help COMMAND flowguard_capture_probe --help)
add_test(NAME capture_probe_bad_args COMMAND flowguard_capture_probe --not-an-option)
set_tests_properties(capture_probe_bad_args PROPERTIES WILL_FAIL TRUE)
set_tests_properties(capture_device_enumerator capture_probe_help capture_probe_bad_args
    PROPERTIES TIMEOUT 15)
