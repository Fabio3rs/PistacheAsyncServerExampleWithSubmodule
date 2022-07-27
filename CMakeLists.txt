set(projectname srv)

cmake_minimum_required(VERSION 3.6.0)
project(${projectname} VERSION 0.1.1)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_DEFAULT 17)
set(CXX17 ON)
set(CMAKE_CXX_EXTENSIONS Off)
set(CMAKE_C_EXTENSIONS Off)

include(CPack)
find_package(PkgConfig)

message("Finding pistache")

add_subdirectory(pistache)
include_directories(BEFORE SYSTEM pistache/include)

set(PISTACHE_LIBRARY pistache)

add_executable(${projectname} rest_server.cc)
target_link_libraries(${projectname} pthread ${PISTACHE_LIBRARY})

