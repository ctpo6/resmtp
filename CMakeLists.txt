# cmake .. (same as 'cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..')
# cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
# cmake -DCMAKE_BUILD_TYPE=Release ..
# cmake -DCMAKE_BUILD_TYPE=Debug ..

project(resmtp)

cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

# if CMAKE_BUILD_TYPE wasn't specified, make it equal to "Release"
IF (NOT CMAKE_BUILD_TYPE)
	SET(
		CMAKE_BUILD_TYPE
		"RelWithDebInfo"
		CACHE STRING
		"Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
		FORCE
	)
ENDIF()

################################################################################
# Macroses
################################################################################

# Standard CMake macroses
#INCLUDE(CheckIncludeFiles)
#INCLUDE(CheckCXXSourceCompiles)
#INCLUDE(CheckSymbolExists)
#INCLUDE(CheckLibraryExists)
INCLUDE(CheckCXXCompilerFlag)

# User-defined macroses
INCLUDE(cmake/ParseDebVersion.cmake)
INCLUDE(cmake/ConfigureLibrary.cmake)

################################################################################
# C++11 compiler
################################################################################
check_cxx_compiler_flag("-std=c++11" CXX11_SUPPORTED)
if (NOT CXX11_SUPPORTED)
	MESSAGE(FATAL_ERROR "C++11 isn't supported!")
endif ()

################################################################################
# Thread library
################################################################################
find_package(Threads)

################################################################################
# Boost
################################################################################
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost REQUIRED COMPONENTS program_options regex system timer thread)

################################################################################
# Other libraries
################################################################################
find_package(OpenSSL REQUIRED)
message(STATUS "")                  

################################################################################
# Compiler flags
################################################################################
add_definitions(-DBOOST_THREAD_USE_LIB)

set(MY_C_WARNING_FLAGS "-Werror -Wall -Wextra -Wredundant-decls -Wformat -Werror=format-security -Wno-parentheses -Wno-unused-parameter")
set(MY_CXX_WARNING_FLAGS "-Werror -Wall -Wextra -Wredundant-decls -Woverloaded-virtual -Wnon-virtual-dtor -Wformat -Werror=format-security -Wno-parentheses -Wno-unused-parameter")

set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb -D_DEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb -D_DEBUG")

set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -ggdb -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -ggdb -DNDEBUG")

set(CMAKE_C_FLAGS "${MY_C_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "-std=c++11 ${MY_CXX_WARNING_FLAGS} ${CMAKE_CXX_FLAGS}")

# for static linking
#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libstdc++ -static-libgcc")

message(STATUS "Build type: '${CMAKE_BUILD_TYPE}'")
message(STATUS "")

################################################################################
# Version
################################################################################
PARSE_DEB_VERSION(DEB)
SET(RESMTP_VERSION "${DEB_VERSION_MAJOR}.${DEB_VERSION_MINOR}.${DEB_VERSION_PATCH}")
add_definitions(-DRESMTP_VERSION="${RESMTP_VERSION}")
message(STATUS "resmtp version: ${RESMTP_VERSION}")
message(STATUS "")


################################################################################
# Build
################################################################################
include_directories(
    src
    ${Boost_INCLUDE_DIRS}
)

file(GLOB HEADERS
    src/*.h
    src/coroutine/*.hpp
    src/net/*.hpp
    src/net/impl/*.hpp
)
file(GLOB SOURCES
    src/*.c
    src/*.cpp
)
file(GLOB CONFIGS
    etc/resmtp/resmtp.conf
    etc/logrotate.d/resmtp
)

# include ${HEADERS} ${CONFIGS} to make them visible in the QtCreator project tree
add_executable(resmtp ${SOURCES} ${HEADERS} ${CONFIGS})
target_link_libraries(resmtp ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})

################################################################################
# Install
################################################################################

IF (NOT SBINDIR)
    SET(SBINDIR "/usr/sbin")
ENDIF ()

IF (NOT SYSCONFDIR)
    SET(SYSCONFDIR "/etc")
ENDIF ()

install(TARGETS resmtp
        RUNTIME DESTINATION ${SBINDIR})

install(FILES etc/resmtp/resmtp.conf
        DESTINATION ${SYSCONFDIR}/resmtp/
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES etc/logrotate.d/resmtp
        DESTINATION ${SYSCONFDIR}/logrotate.d/
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

#install(DIRECTORY DESTINATION /spool/logs/resmtp DIRECTORY_PERMISSIONS
#    OWNER_WRITE OWNER_READ OWNER_EXECUTE
#    GROUP_READ GROUP_EXECUTE
#    WORLD_READ WORLD_EXECUTE
