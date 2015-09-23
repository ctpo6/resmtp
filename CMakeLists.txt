# resmtp

project(resmtp)

cmake_minimum_required(VERSION 2.8.5)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost REQUIRED COMPONENTS filesystem program_options regex system timer thread)
find_package(Protobuf REQUIRED)

add_definitions(-O2 -std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)
#add_definitions(-g -O1 -std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)
#add_definitions(-g -O0 -std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)

#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libstdc++ -static-libgcc")

include_directories(
  .
  ${Boost_INCLUDE_DIRS}
  ${PROTOBUF_INCLUDE_DIRS}
	# required for protobuf-generated sources
  ${CMAKE_BINARY_DIR}
)

file(GLOB HEADERS
  *.h
  *.hpp
  net/*.hpp
  net/impl/*.hpp
  rc_clients/*.h
  yplatform/*.h
)
file(GLOB SOURCES
  *.c
  *.cpp
  rc_clients/*.cpp
)
file(GLOB PROTO_FILES rc.proto)

protobuf_generate_cpp(PROTO_SOURCES PROTO_HEADERS rc.proto)

add_custom_command(OUTPUT ${PROTO_SOURCES} ${PROTO_HEADERS}
                   COMMAND protoc --cpp_out=. ${PROTO_FILES}
                   MAIN_DEPENDENCY ${PROTO_FILES}
                   COMMENT "Generating from *.proto"
                   VERBATIM)

add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES} ${PROTO_SOURCES} ${PROTO_HEADERS})

target_link_libraries(${PROJECT_NAME} ${PROTOBUF_LIBRARIES} ${Boost_LIBRARIES}
  ssl crypto expat spf2 opendkim)
