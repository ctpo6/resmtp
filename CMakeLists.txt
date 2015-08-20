# resmtp

project(resmtp)

cmake_minimum_required(VERSION 2.8.5)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost REQUIRED COMPONENTS filesystem program_options regex system timer)
find_package(Protobuf REQUIRED)

add_definitions(-O2 -std=c++14 -march=core2 -mfpmath=sse -Wall -Wno-parentheses)
#add_definitions(-g -O1 -std=c++14 -march=core2 -mfpmath=sse -Wall -Wno-parentheses)
#add_definitions(-g -O0 -std=c++14 -march=core2 -mfpmath=sse -Wall -Wno-parentheses)

#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libstdc++ -static-libgcc")

#add_subdirectory(proto)
#add_subdirectory(test)

include_directories(
  .
  ${Boost_INCLUDE_DIRS}
  ${PROTOBUF_INCLUDE_DIRS}
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

# на случай, если нужно будет реализовать исполнение скрипта беред билдом
#add_custom_target(
#    preBuild
#    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/pre_build.py
#)

protobuf_generate_cpp(PROTO_SOURCES PROTO_HEADERS rc.proto)

add_custom_command(OUTPUT ${PROTO_SOURCES} ${PROTO_HEADERS}
                   COMMAND protoc --cpp_out=. ${PROTO_FILES}
                   MAIN_DEPENDENCY ${PROTO_FILES}
                   COMMENT "Generating from *.proto"
                   VERBATIM)


#add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES} build_number)
add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES} ${PROTO_SOURCES} ${PROTO_HEADERS})

#target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES}
#  nanomsg cairo ssimproto yorbit pthread anl pixman-1 png12 fontconfig freetype z expat)


target_link_libraries(${PROJECT_NAME} ${PROTOBUF_LIBRARIES} ${Boost_LIBRARIES}
  libexpat libspf2 libopendkim)

#add_dependencies(${PROJECT_NAME} yorbit ssimproto)

# на случай, если нужно будет реализовать исполнение скрипта беред билдом
#add_dependencies(preBuild ${PROJECT_NAME})

# инкремент номера билда - делается ПОСЛЕ билда - чтобы не инкрементировался при неудачных билдах
# хранится в файле build_number, который инклудится в исходник
#add_custom_command(TARGET ${PROJECT_NAME}
#                   POST_BUILD
#                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/inc_build_number.py)

