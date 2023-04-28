cmake_minimum_required(VERSION 3.20)

project(DES_WeakKeys)

add_executable(${PROJECT_NAME}
    src/main.cpp
    thirdparty/cppDES/des.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC thirdparty/cppDES)
target_compile_options(${PROJECT_NAME} PUBLIC -Wall -Wextra -g3)