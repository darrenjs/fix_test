cmake_minimum_required(VERSION 3.21)
project(fix_test)

set(CMAKE_CXX_STANDARD 14)

add_executable(fix_test main.cpp)
target_link_libraries(fix_test PRIVATE crypto)
target_link_libraries(fix_test PRIVATE ssl)
