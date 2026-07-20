cmake_minimum_required(VERSION 3.25)
project(KASA VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(GLEW REQUIRED)

add_library(kasa_engine STATIC
        encryption_engine.cpp
        encryption_engine.h)

target_include_directories(kasa_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kasa_engine PUBLIC OpenSSL::Crypto)

set(KASA_PLATFORM_RESOURCES)
if(WIN32)
    list(APPEND KASA_PLATFORM_RESOURCES resources/KASA.rc)
endif()

add_executable(encryption WIN32 main.cpp
        AppWindow.cpp
        AppWindow.h
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
    add_executable(kasa_engine_tests tests/encryption_engine_tests.cpp)
    target_link_libraries(kasa_engine_tests PRIVATE kasa_engine)
    add_test(NAME kasa_engine_tests COMMAND kasa_engine_tests)
endif()
