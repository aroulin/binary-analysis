cmake_minimum_required(VERSION 3.5.1)
project(binary_analysis)

set(CMAKE_CXX_STANDARD 11)

add_definitions(-DPACKAGE)
add_definitions(-DPACKAGE_VERSION)

add_library(loader loader.h loader.cc)
target_link_libraries(loader bfd)

add_executable(loader_demo loader_demo.cc)
add_executable(basic_capstone_linear basic_capstone_linear.cc)
add_executable(basic_capstone_recursive basic_capstone_recursive.cc)
add_executable(capstone_gadget_finder capstone_gadget_finder.cc)

target_link_libraries(loader_demo loader)
target_link_libraries(basic_capstone_linear capstone loader)
target_link_libraries(basic_capstone_recursive capstone loader)
target_link_libraries(capstone_gadget_finder capstone loader)