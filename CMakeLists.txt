cmake_minimum_required(VERSION 4.0)
project(encryption)

set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
set(VCPKG_TARGET_TRIPLET "x64-mingw-dynamic" CACHE STRING "")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

find_package(imgui CONFIG REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(GLEW REQUIRED)

add_executable(encryption WIN32 main.cpp
        encryption_engine.cpp
        encryption_engine.h
        AppWindow.cpp
        AppWindow.h)


target_link_libraries(encryption PRIVATE
        imgui::imgui
        glfw
        opengl32
        OpenSSL::Crypto
        GLEW::GLEW
)
