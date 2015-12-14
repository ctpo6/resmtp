project(test)

cmake_minimum_required(VERSION 2.8.5)

#set(Boost_USE_STATIC_LIBS OFF)
#set(Boost_USE_MULTITHREADED ON)
#set(Boost_USE_STATIC_RUNTIME OFF)

#find_package(Boost REQUIRED COMPONENTS thread system timer)
#find_package(Threads)

#include_directories(
#  ${Boost_INCLUDE_DIRS}
#)

#file(GLOB HDR pdbg.h)
file(GLOB SRC_TEST_WRR test_wrr.cpp)

set(CMAKE_CXX_FLAGS "-O2 -std=c++11 -Wall -Wno-parentheses")

add_executable(test_wrr ${SRC_TEST_WRR})

