cmake_minimum_required(VERSION 3.14)
project(binary_analysis)

set(CMAKE_CXX_STANDARD 17)

add_definitions(-DPACKAGE)
add_definitions(-DPACKAGE_VERSION)

add_executable(loader_demo main.cpp loader.h loader.cc)

target_link_libraries(loader_demo bfd)