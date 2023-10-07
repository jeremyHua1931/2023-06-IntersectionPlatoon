cmake_minimum_required(VERSION 3.10.2)
project(testCPP)

set(CMAKE_CXX_STANDARD 14)

add_executable(optimizeSpeedAcc optimizeSpeedAcc.cpp)
target_link_libraries(optimizeSpeedAcc ipopt)

