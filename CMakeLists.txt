cmake_minimum_required(VERSION 3.25)
project(KASA VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(GLEW REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
set(KASA_RELEASE_VERSION "1.1.0-test.2" CACHE STRING "Installed release version")
set(KASA_UPDATE_PUBLIC_KEY_HEX "ba6cb46d90a411d4641a952058d7e97cd5cfebb6a3a2de2d8975745053daf745" CACHE STRING "Pinned Ed25519 PUBLIC key, lowercase hex; empty disables preparation")
if(NOT KASA_UPDATE_PUBLIC_KEY_HEX STREQUAL "")
    string(LENGTH "${KASA_UPDATE_PUBLIC_KEY_HEX}" KASA_KEY_LENGTH)
    if(NOT KASA_KEY_LENGTH EQUAL 64 OR NOT KASA_UPDATE_PUBLIC_KEY_HEX MATCHES "^[0-9a-f]+$" OR KASA_UPDATE_PUBLIC_KEY_HEX MATCHES "^0+$")
        message(FATAL_ERROR "Update public key must be 64 lowercase hex characters and nonzero")
    endif()
endif()
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/resources/KASA.rc" KASA_VERSION_RESOURCE)
string(FIND "${KASA_VERSION_RESOURCE}" "\"${KASA_RELEASE_VERSION}\\0\"" KASA_VERSION_POSITION)
if(KASA_VERSION_POSITION EQUAL -1)
    message(FATAL_ERROR "KASA_RELEASE_VERSION must match resources/KASA.rc before building an update-aware binary")
endif()

add_library(kasa_update_verification STATIC update_manifest.cpp update_manifest.h update_download.cpp update_download.h update_staging.cpp update_staging.h update_job.cpp update_job.h)
target_include_directories(kasa_update_verification PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kasa_update_verification PUBLIC OpenSSL::Crypto PRIVATE nlohmann_json::nlohmann_json winhttp advapi32)

add_library(kasa_engine STATIC
        encryption_engine.cpp
        encryption_engine.h
        plaintext_output.h
        preview_text.cpp
        preview_text.h
        preview_image.cpp
        preview_image.h
        verified_save.cpp
        verified_save.h)

target_include_directories(kasa_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kasa_engine PUBLIC OpenSSL::Crypto windowscodecs ole32 uuid)

set(KASA_PLATFORM_RESOURCES)
if(WIN32)
    list(APPEND KASA_PLATFORM_RESOURCES resources/KASA.rc)
endif()

add_executable(encryption WIN32 main.cpp
        update_check.cpp
        PreviewWindow.cpp
        PreviewWindow.h
        preview_job.h
        preview_input.h
        startup_arguments.h
        AppWindow.cpp
        AppWindow.h
        batch_save.h
        batch_runner.h
        output_path.h
        operation_password.h
        ${KASA_PLATFORM_RESOURCES})

target_link_libraries(encryption PRIVATE
        kasa_update_verification
        kasa_engine
        imgui::imgui
        glfw
        opengl32
        GLEW::GLEW
        nlohmann_json::nlohmann_json
        winhttp
        advapi32
)
target_compile_definitions(encryption PRIVATE KASA_RELEASE_VERSION="${KASA_RELEASE_VERSION}")
target_compile_definitions(encryption PRIVATE KASA_UPDATE_PUBLIC_KEY_HEX="${KASA_UPDATE_PUBLIC_KEY_HEX}")

set_target_properties(encryption PROPERTIES OUTPUT_NAME "KASA")

if(MINGW)
    target_link_options(encryption PRIVATE -static-libgcc -static-libstdc++)
endif()

include(CTest)
add_executable(kasa_update_helper WIN32 update_helper.cpp)
target_link_libraries(kasa_update_helper PRIVATE shell32 advapi32)
set_target_properties(kasa_update_helper PROPERTIES OUTPUT_NAME "KASA-Updater-${KASA_RELEASE_VERSION}")
if(MINGW)
    target_link_options(kasa_update_helper PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()
add_library(kasa_update_publisher STATIC update_publisher.cpp)
target_include_directories(kasa_update_publisher PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kasa_update_publisher PUBLIC OpenSSL::Crypto PRIVATE nlohmann_json::nlohmann_json)
add_executable(kasa_publisher publisher_main.cpp)
target_link_libraries(kasa_publisher PRIVATE kasa_update_publisher crypt32 advapi32 shell32 ole32)
if(MINGW)
    target_link_options(kasa_publisher PRIVATE -municode -static-libgcc -static-libstdc++)
endif()
if(BUILD_TESTING)
    add_executable(kasa_update_release_verify tests/update_release_verify.cpp)
    target_link_libraries(kasa_update_release_verify PRIVATE kasa_update_verification)
    target_compile_definitions(kasa_update_release_verify PRIVATE KASA_UPDATE_PUBLIC_KEY_HEX="${KASA_UPDATE_PUBLIC_KEY_HEX}")
    add_executable(kasa_update_helper_probe tests/update_helper_probe.cpp)
    if(MINGW)
        target_link_options(kasa_update_helper_probe PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
    add_executable(kasa_update_handoff_probe tests/update_handoff_probe.cpp)
    target_link_libraries(kasa_update_handoff_probe PRIVATE kasa_update_publisher kasa_update_verification)
    add_executable(kasa_update_publisher_tests tests/update_publisher_tests.cpp)
    target_link_libraries(kasa_update_publisher_tests PRIVATE kasa_update_publisher kasa_update_verification)
    add_test(NAME kasa_update_publisher_tests COMMAND kasa_update_publisher_tests)
    add_executable(kasa_update_ui_policy_tests tests/update_ui_policy_tests.cpp)
    target_include_directories(kasa_update_ui_policy_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_update_ui_policy_tests COMMAND kasa_update_ui_policy_tests)
    add_executable(kasa_update_job_tests tests/update_job_tests.cpp)
    target_link_libraries(kasa_update_job_tests PRIVATE kasa_update_verification nlohmann_json::nlohmann_json)
    add_test(NAME kasa_update_job_tests COMMAND kasa_update_job_tests)
    add_executable(kasa_update_staging_tests tests/update_staging_tests.cpp)
    target_link_libraries(kasa_update_staging_tests PRIVATE kasa_update_verification nlohmann_json::nlohmann_json)
    add_test(NAME kasa_update_staging_tests COMMAND kasa_update_staging_tests)
    add_executable(kasa_update_download_tests tests/update_download_tests.cpp)
    target_link_libraries(kasa_update_download_tests PRIVATE kasa_update_verification nlohmann_json::nlohmann_json)
    add_test(NAME kasa_update_download_tests COMMAND kasa_update_download_tests)
    add_executable(kasa_update_manifest_tests tests/update_manifest_tests.cpp)
    target_link_libraries(kasa_update_manifest_tests PRIVATE kasa_update_verification nlohmann_json::nlohmann_json)
    add_test(NAME kasa_update_manifest_tests COMMAND kasa_update_manifest_tests)
    add_executable(kasa_update_check_tests tests/update_check_smoke.cpp update_check.cpp)
    target_include_directories(kasa_update_check_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(kasa_update_check_tests PRIVATE nlohmann_json::nlohmann_json winhttp)
    target_compile_definitions(kasa_update_check_tests PRIVATE KASA_RELEASE_VERSION="${KASA_RELEASE_VERSION}")
    add_test(NAME kasa_update_check_tests COMMAND kasa_update_check_tests)
    add_executable(kasa_update_metadata_tests tests/update_metadata_tests.cpp)
    target_include_directories(kasa_update_metadata_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(kasa_update_metadata_tests PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME kasa_update_metadata_tests COMMAND kasa_update_metadata_tests)
    add_executable(kasa_update_policy_tests tests/update_policy_tests.cpp)
    target_include_directories(kasa_update_policy_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_update_policy_tests COMMAND kasa_update_policy_tests)
    add_executable(kasa_source_deletion_policy_tests tests/source_deletion_policy_tests.cpp)
    target_include_directories(kasa_source_deletion_policy_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_source_deletion_policy_tests COMMAND kasa_source_deletion_policy_tests)
    add_executable(kasa_ui_palette_tests tests/ui_palette_tests.cpp)
    target_include_directories(kasa_ui_palette_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_ui_palette_tests COMMAND kasa_ui_palette_tests)
    add_executable(kasa_batch_runner_tests tests/batch_runner_tests.cpp)
    target_link_libraries(kasa_batch_runner_tests PRIVATE kasa_engine)
    add_test(NAME kasa_batch_runner_tests COMMAND kasa_batch_runner_tests)
    add_executable(kasa_batch_save_tests tests/batch_save_tests.cpp)
    target_link_libraries(kasa_batch_save_tests PRIVATE kasa_engine)
    add_test(NAME kasa_batch_save_tests COMMAND kasa_batch_save_tests)
    add_executable(kasa_preview_lifecycle_tests tests/preview_lifecycle_tests.cpp)
    target_link_libraries(kasa_preview_lifecycle_tests PRIVATE kasa_engine shell32)
    add_test(NAME kasa_preview_lifecycle_tests COMMAND kasa_preview_lifecycle_tests)
    add_executable(kasa_preview_image_tests tests/preview_image_tests.cpp)
    target_link_libraries(kasa_preview_image_tests PRIVATE kasa_engine)
    add_test(NAME kasa_preview_image_tests COMMAND kasa_preview_image_tests)
    add_executable(kasa_preview_text_tests tests/preview_text_tests.cpp)
    target_link_libraries(kasa_preview_text_tests PRIVATE kasa_engine)
    add_test(NAME kasa_preview_text_tests COMMAND kasa_preview_text_tests)
    add_executable(kasa_preview_memory_tests tests/preview_memory_tests.cpp)
    target_link_libraries(kasa_preview_memory_tests PRIVATE kasa_engine)
    add_test(NAME kasa_preview_memory_tests COMMAND kasa_preview_memory_tests)
    add_executable(kasa_preview_policy_tests tests/preview_policy_tests.cpp)
    target_include_directories(kasa_preview_policy_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_preview_policy_tests COMMAND kasa_preview_policy_tests)
    add_executable(kasa_batch_tests tests/batch_state_tests.cpp)
    target_include_directories(kasa_batch_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_batch_tests COMMAND kasa_batch_tests)
    add_executable(kasa_password_tests tests/operation_password_tests.cpp)
    target_include_directories(kasa_password_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(kasa_password_tests PRIVATE OpenSSL::Crypto)
    add_test(NAME kasa_password_tests COMMAND kasa_password_tests)
    add_executable(kasa_plaintext_tests tests/plaintext_output_tests.cpp)
    target_include_directories(kasa_plaintext_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME kasa_plaintext_tests COMMAND kasa_plaintext_tests)
    add_executable(kasa_engine_tests tests/encryption_engine_tests.cpp)
    target_link_libraries(kasa_engine_tests PRIVATE kasa_engine)
    add_test(NAME kasa_engine_tests COMMAND kasa_engine_tests)
    add_executable(kasa_save_tests tests/verified_save_tests.cpp verified_save.cpp)
    target_include_directories(kasa_save_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(kasa_save_tests PRIVATE KASA_SAVE_TESTING)
    target_link_libraries(kasa_save_tests PRIVATE OpenSSL::Crypto)
    add_test(NAME kasa_save_tests COMMAND kasa_save_tests)
endif()
