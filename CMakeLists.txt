cmake_minimum_required(VERSION 3.25)
project(KASA VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(GLEW REQUIRED)

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
        kasa_engine
        imgui::imgui
        glfw
        opengl32
        GLEW::GLEW
)

set_target_properties(encryption PROPERTIES OUTPUT_NAME "KASA")

if(MINGW)
    target_link_options(encryption PRIVATE -static-libgcc -static-libstdc++)
endif()

include(CTest)
if(BUILD_TESTING)
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
