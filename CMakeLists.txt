cmake_minimum_required(VERSION 3.21)
project(FlowGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Charts Network)
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
    src/capture/capture_session.cpp
    src/capture/capture_buffer.h
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

add_executable(flowguard_session_tests tests/capture_session_tests.cpp)
target_link_libraries(flowguard_session_tests PRIVATE flowguard_capture)
flowguard_configure_cpp(flowguard_session_tests)
add_executable(flowguard_live_tests tests/capture_live_tests.cpp)
target_link_libraries(flowguard_live_tests PRIVATE flowguard_capture)
flowguard_configure_cpp(flowguard_live_tests)

set_target_properties(flowguard_capture flowguard_capture_probe
    flowguard_contracts_check flowguard_capture_tests flowguard_session_tests flowguard_live_tests PROPERTIES
    AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

qt_add_executable(FlowGuard
    src/main.cpp
    src/ui/main_window.cpp
    src/ui/main_window.h
    src/core/packet_types.h)
target_include_directories(FlowGuard PRIVATE src)
target_link_libraries(FlowGuard PRIVATE Qt6::Widgets flowguard_capture)
flowguard_configure_cpp(FlowGuard)
file(GENERATE OUTPUT "$<TARGET_FILE_DIR:FlowGuard>/FlowGuard使用指南.html"
    INPUT "${CMAKE_CURRENT_SOURCE_DIR}/docs/FlowGuard使用指南.html")

enable_testing()
add_test(NAME stage0_smoke COMMAND FlowGuard --smoke-test)
set_tests_properties(stage0_smoke PROPERTIES TIMEOUT 15
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FLOWGUARD_ACCEPTANCE=1;FLOWGUARD_LOG_ROOT=${CMAKE_CURRENT_BINARY_DIR}/smoke-runs")

# Parsing stays independent of Qt and Npcap so captured and offline packets share it.
add_library(flowguard_parser STATIC src/parser/packet_parser.cpp)
set_target_properties(flowguard_parser PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
target_include_directories(flowguard_parser PUBLIC src)
target_link_libraries(FlowGuard PRIVATE flowguard_parser)
add_executable(packet_parser_tests tests/packet_parser_tests.cpp)
set_target_properties(packet_parser_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
target_link_libraries(packet_parser_tests PRIVATE flowguard_parser)
if(MSVC)
    target_compile_options(flowguard_parser PRIVATE /W4 /utf-8)
    target_compile_options(packet_parser_tests PRIVATE /W4 /utf-8)
endif()
add_test(NAME packet_parser COMMAND packet_parser_tests)
set_tests_properties(packet_parser PROPERTIES TIMEOUT 15)
add_test(NAME capture_device_enumerator COMMAND flowguard_capture_tests)
add_test(NAME capture_probe_help COMMAND flowguard_capture_probe --help)
add_test(NAME capture_probe_bad_args COMMAND flowguard_capture_probe --not-an-option)
add_test(NAME capture_session_unit COMMAND flowguard_session_tests)
add_test(NAME capture_loopback_live COMMAND flowguard_live_tests)
set_tests_properties(capture_session_unit PROPERTIES TIMEOUT 20)
set_tests_properties(capture_loopback_live PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 LABELS "hardware")
set_tests_properties(capture_probe_bad_args PROPERTIES WILL_FAIL TRUE)
set_tests_properties(capture_device_enumerator capture_probe_help capture_probe_bad_args
    PROPERTIES TIMEOUT 15)

add_library(flowguard_storage STATIC src/storage/pcap_reader.cpp src/storage/pcap_writer.cpp)
target_include_directories(flowguard_storage PUBLIC src)
flowguard_configure_cpp(flowguard_storage)
add_executable(flowguard_reader_tests tests/pcap_reader_tests.cpp)
target_link_libraries(flowguard_reader_tests PRIVATE flowguard_storage flowguard_parser)
flowguard_configure_cpp(flowguard_reader_tests)
add_executable(flowguard_offline_probe src/parser/offline_probe.cpp)
target_link_libraries(flowguard_offline_probe PRIVATE flowguard_storage flowguard_parser)
flowguard_configure_cpp(flowguard_offline_probe)
set_target_properties(flowguard_storage flowguard_reader_tests flowguard_offline_probe PROPERTIES
    AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_test(NAME pcap_reader COMMAND flowguard_reader_tests)
add_test(NAME offline_parser_fixture COMMAND flowguard_offline_probe "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/ethernet-ipv4-udp.pcap")
set_tests_properties(pcap_reader offline_parser_fixture PROPERTIES TIMEOUT 15)

add_executable(flowguard_capture_parser_tests tests/capture_parser_live_tests.cpp)
target_link_libraries(flowguard_capture_parser_tests PRIVATE flowguard_capture flowguard_parser)
flowguard_configure_cpp(flowguard_capture_parser_tests)
set_target_properties(flowguard_capture_parser_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_test(NAME capture_parser_loopback_live COMMAND flowguard_capture_parser_tests)
set_tests_properties(capture_parser_loopback_live PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 LABELS "hardware")

# Stage-1 end-to-end verification through the teammate's real CaptureSession.
add_executable(flowguard_live_parse_probe src/parser/live_parse_probe.cpp)
target_link_libraries(flowguard_live_parse_probe PRIVATE flowguard_capture flowguard_parser)
flowguard_configure_cpp(flowguard_live_parse_probe)
set_target_properties(flowguard_live_parse_probe PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

# Optional independent protocol oracle. The path is a local CMake cache value.
set(FLOWGUARD_TSHARK_EXECUTABLE "" CACHE FILEPATH "Optional installed TShark for stage-1 field comparison")
if(FLOWGUARD_TSHARK_EXECUTABLE)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME parser_wireshark_reference
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/tshark_compare.py"
        --probe "$<TARGET_FILE:flowguard_offline_probe>" --tshark "${FLOWGUARD_TSHARK_EXECUTABLE}"
        --pcap "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap"
        --manifest "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.json")
    set_tests_properties(parser_wireshark_reference PROPERTIES TIMEOUT 30)
endif()

add_executable(flowguard_parser_corpus_tests tests/parser_corpus_tests.cpp)
target_link_libraries(flowguard_parser_corpus_tests PRIVATE flowguard_parser flowguard_storage)
flowguard_configure_cpp(flowguard_parser_corpus_tests)
set_target_properties(flowguard_parser_corpus_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_test(NAME parser_protocol_boundaries COMMAND flowguard_parser_corpus_tests "tests/data/stage1-protocols.pcap"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
set_tests_properties(parser_protocol_boundaries PROPERTIES TIMEOUT 30)

# Stage 2 belongs to He Junjie; Qt remains a consumer in the next stage.
add_library(flowguard_statistics STATIC src/statistics/statistics.cpp)
target_include_directories(flowguard_statistics PUBLIC src)
flowguard_configure_cpp(flowguard_statistics)
add_library(flowguard_processing STATIC src/processing/processing_session.cpp src/alerts/alert_engine.cpp)
target_include_directories(flowguard_processing PUBLIC src)
target_link_libraries(flowguard_processing PUBLIC flowguard_capture flowguard_parser flowguard_storage flowguard_statistics)
flowguard_configure_cpp(flowguard_processing)
add_executable(flowguard_processing_probe src/processing/processing_probe.cpp)
target_link_libraries(flowguard_processing_probe PRIVATE flowguard_processing)
flowguard_configure_cpp(flowguard_processing_probe)
set_target_properties(flowguard_statistics flowguard_processing flowguard_processing_probe PROPERTIES
    AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_executable(flowguard_stage2_tests tests/stage2_tests.cpp)
target_link_libraries(flowguard_stage2_tests PRIVATE flowguard_processing)
flowguard_configure_cpp(flowguard_stage2_tests)
set_target_properties(flowguard_stage2_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_test(NAME stage2_processing_storage COMMAND flowguard_stage2_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(stage2_processing_storage PROPERTIES TIMEOUT 30)
add_executable(flowguard_alert_tests tests/alert_tests.cpp)
target_link_libraries(flowguard_alert_tests PRIVATE flowguard_processing)
flowguard_configure_cpp(flowguard_alert_tests)
set_target_properties(flowguard_alert_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_test(NAME alert_detection COMMAND flowguard_alert_tests "${CMAKE_CURRENT_BINARY_DIR}/alert-test.pcap")
set_tests_properties(alert_detection PROPERTIES TIMEOUT 30)

# Stage 3: Qt adapter, required charts, process resources, durable run evidence.
execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE FLOWGUARD_GIT_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND git status --porcelain WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE FLOWGUARD_GIT_STATUS OUTPUT_STRIP_TRAILING_WHITESPACE)
if(FLOWGUARD_GIT_STATUS)
    set(FLOWGUARD_GIT_DIRTY "true")
else()
    set(FLOWGUARD_GIT_DIRTY "false")
endif()
configure_file(src/build_info.h.in generated/build_info.h @ONLY)
add_library(flowguard_ui_support STATIC
    src/ui/packet_interpretation.cpp src/ui/display_filter.cpp src/ui/packet_model.cpp src/ui/pcap_pager.cpp src/ui/device_selector.cpp src/ui/device_system_info.cpp src/ui/alert_panel.cpp
    src/storage/recording_files.cpp
    src/monitoring/resource_sampler.cpp src/monitoring/run_recorder.cpp)
target_include_directories(flowguard_ui_support PUBLIC src PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(flowguard_ui_support PUBLIC flowguard_processing Qt6::Widgets Qt6::Network psapi iphlpapi)
flowguard_configure_cpp(flowguard_ui_support)
add_executable(flowguard_pcap_pager_tests tests/pcap_pager_tests.cpp)
target_link_libraries(flowguard_pcap_pager_tests PRIVATE flowguard_ui_support)
flowguard_configure_cpp(flowguard_pcap_pager_tests)
add_test(NAME pcap_complete_paging COMMAND flowguard_pcap_pager_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(pcap_complete_paging PROPERTIES TIMEOUT 30)
target_sources(FlowGuard PRIVATE src/ui/chart_panel.cpp)
target_link_libraries(FlowGuard PRIVATE flowguard_ui_support Qt6::Charts)
qt_add_resources(FlowGuard icons PREFIX "/" BASE assets FILES assets/flowguard.png)
if(WIN32)
    target_sources(FlowGuard PRIVATE assets/flowguard.rc)
endif()
add_executable(flowguard_stage3_support_tests tests/stage3_support_tests.cpp)
target_link_libraries(flowguard_stage3_support_tests PRIVATE flowguard_ui_support)
flowguard_configure_cpp(flowguard_stage3_support_tests)
add_test(NAME stage3_support COMMAND flowguard_stage3_support_tests)
set_tests_properties(stage3_support PROPERTIES TIMEOUT 20 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
add_test(NAME stage3_gui_file COMMAND FlowGuard --accept-file "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(stage3_gui_file PROPERTIES TIMEOUT 20
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FLOWGUARD_ACCEPTANCE=1;FLOWGUARD_LOG_ROOT=${CMAKE_CURRENT_BINARY_DIR}/acceptance-runs")
find_package(Qt6 REQUIRED COMPONENTS Test)
add_executable(flowguard_recording_tests tests/recording_gui_tests.cpp src/ui/main_window.cpp src/ui/chart_panel.cpp)
target_link_libraries(flowguard_recording_tests PRIVATE flowguard_ui_support Qt6::Charts Qt6::Test)
flowguard_configure_cpp(flowguard_recording_tests)
add_test(NAME recording_workflow COMMAND flowguard_recording_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(recording_workflow PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77 LABELS "hardware"
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FLOWGUARD_ACCEPTANCE=1;FLOWGUARD_LOG_ROOT=${CMAKE_CURRENT_BINARY_DIR}/recording-test-runs")
add_executable(flowguard_storage_selection_tests tests/storage_selection_tests.cpp src/ui/main_window.cpp src/ui/chart_panel.cpp)
target_link_libraries(flowguard_storage_selection_tests PRIVATE flowguard_ui_support Qt6::Charts Qt6::Test)
flowguard_configure_cpp(flowguard_storage_selection_tests)
add_test(NAME user_selected_storage COMMAND flowguard_storage_selection_tests)
set_tests_properties(user_selected_storage PROPERTIES TIMEOUT 30
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FLOWGUARD_ACCEPTANCE=1;FLOWGUARD_LOG_ROOT=")
add_executable(flowguard_alert_gui_tests tests/alert_gui_tests.cpp src/ui/main_window.cpp src/ui/chart_panel.cpp)
target_link_libraries(flowguard_alert_gui_tests PRIVATE flowguard_ui_support Qt6::Charts Qt6::Test)
flowguard_configure_cpp(flowguard_alert_gui_tests)
add_test(NAME alert_gui_integration COMMAND flowguard_alert_gui_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/alerts-demo.pcap" "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/alerts-normal.pcap"
    "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(alert_gui_integration PROPERTIES TIMEOUT 60
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FLOWGUARD_ACCEPTANCE=1;FLOWGUARD_LOG_ROOT=${CMAKE_CURRENT_BINARY_DIR}/alert-test-runs")
add_executable(flowguard_stage3_gui_tests tests/stage3_gui_tests.cpp src/ui/main_window.cpp src/ui/chart_panel.cpp)
set_target_properties(flowguard_stage3_gui_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/gui-test-bin")
target_link_libraries(flowguard_stage3_gui_tests PRIVATE flowguard_ui_support Qt6::Charts Qt6::Test)
flowguard_configure_cpp(flowguard_stage3_gui_tests)
add_test(NAME stage3_gui_integration COMMAND flowguard_stage3_gui_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(stage3_gui_integration PROPERTIES TIMEOUT 40 LABELS "hardware"
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;FLOWGUARD_ACCEPTANCE=1;FLOWGUARD_LOG_ROOT=${CMAKE_CURRENT_BINARY_DIR}/gui-integration-runs")
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME stage3_run_analysis COMMAND "${Python3_EXECUTABLE}" -m unittest discover -s tests -p test_run_analysis.py
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Local course-required acceptance additions: full header details.
add_executable(flowguard_required_fields_tests tests/required_header_fields_tests.cpp)
target_link_libraries(flowguard_required_fields_tests PRIVATE flowguard_parser flowguard_storage)
flowguard_configure_cpp(flowguard_required_fields_tests)
set_target_properties(flowguard_required_fields_tests PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
add_test(NAME required_header_fields COMMAND flowguard_required_fields_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(required_header_fields PROPERTIES TIMEOUT 30)

# Packet interpretation uses parsed fields, including incomplete/fragmented packets.
add_executable(flowguard_packet_interpretation_tests tests/packet_interpretation_tests.cpp)
target_link_libraries(flowguard_packet_interpretation_tests PRIVATE flowguard_ui_support)
flowguard_configure_cpp(flowguard_packet_interpretation_tests)
add_test(NAME packet_interpretation COMMAND flowguard_packet_interpretation_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/stage1-protocols.pcap")
set_tests_properties(packet_interpretation PROPERTIES TIMEOUT 20)
