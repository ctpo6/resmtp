# resmtp

project(resmtp)

cmake_minimum_required(VERSION 2.8.5)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost REQUIRED COMPONENTS filesystem program_options regex system timer thread)

add_definitions(-O2 -std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)
#add_definitions(-g -O1 -std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)
#add_definitions(-g -O0 -std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)

#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libstdc++ -static-libgcc")

include_directories(
  .
  ${Boost_INCLUDE_DIRS}
)

file(GLOB HEADERS
  *.h
  *.hpp
  net/*.hpp
  net/impl/*.hpp
  yplatform/*.h
)
file(GLOB SOURCES
  *.c
  *.cpp
)

add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES})

target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES}
  ssl crypto expat spf2 opendkim)
