cmake_minimum_required(VERSION 3.20)

project(
    Chaos
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(Chaos INTERFACE)

target_include_directories(Chaos INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/Chaos>
)

add_subdirectory(ChaosTests)
