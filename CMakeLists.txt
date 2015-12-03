#
# resmtp - SMTP frontend relay
#
project(resmtp)

cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)


################################################################################
# Defaults
################################################################################
OPTION(DEBUG_MODE          "Enable debug output [default: OFF]" OFF)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: ON]" ON)


################################################################################
# Macroses
################################################################################

# Standard CMake macroses
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckCXXSourceCompiles)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckLibraryExists)

# User-defined macroses
INCLUDE(cmake/ParseDebVersion.cmake)
#INCLUDE(cmake/RenameModule.cmake)
INCLUDE(cmake/ConfigurePackage.cmake)
INCLUDE(cmake/ConfigureLibrary.cmake)
INCLUDE(CheckCXXCompilerFlag)


################################################################################
# C++11 compiler
################################################################################
check_cxx_compiler_flag("-std=c++11" CXX11_SUPPORTED)
if (NOT CXX11_SUPPORTED)
	MESSAGE(FATAL_ERROR "C++11 isn't supported!")
endif (NOT CXX11_SUPPORTED)


################################################################################
# Version
################################################################################
#PARSE_DEB_VERSION(DEB)
#SET(MAILCORE_VERSION         "${MAILCORE_VERSION_MAJOR}.${MAILCORE_VERSION_MINOR}.${MAILCORE_VERSION_PATCH}")
#MESSAGE(STATUS "#### Version is: ${MAILCORE_VERSION}")


################################################################################
# Boost
################################################################################
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost REQUIRED COMPONENTS filesystem program_options regex system timer thread)

################################################################################
# Other libraries
################################################################################
find_package(OpenSSL REQUIRED)
configure_library(spf2/spf.h "/usr/include /usr/local/include"
                  spf2 "/usr/lib /usr/local/lib")
configure_library(opendkim/dkim.h "/usr/include /usr/local/include"
                  opendkim "/usr/lib /usr/local/lib")
message(STATUS "")                  


################################################################################
# Print options
################################################################################
message(STATUS ----------------------------------------------------------------)
message(STATUS "ENABLE_OPTIMIZATION is " ${ENABLE_OPTIMIZATION})
message(STATUS "DEBUG_MODE is " ${DEBUG_MODE})
message(STATUS ----------------------------------------------------------------)
message(STATUS "")                  


################################################################################
# Compiler flags
################################################################################
add_definitions(-std=c++11 -Wall -Wno-parentheses -DBOOST_THREAD_USE_LIB)
IF (ENABLE_OPTIMIZATION MATCHES "ON")
	add_definitions(-O2)
ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")

IF (DEBUG_MODE MATCHES "ON")
	add_definitions(-g -D_DEBUG)
ENDIF(DEBUG_MODE MATCHES "ON")

#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libstdc++ -static-libgcc")


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
    etc/*.conf
)

add_executable(resmtp ${HEADERS} ${SOURCES} ${CONFIGS})
target_link_libraries(resmtp ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${HAVE_spf2} ${HAVE_opendkim})

################################################################################
# Install
################################################################################

IF(NOT SBINDIR)
    SET(SBINDIR "/usr/sbin")
ENDIF(NOT SBINDIR)

IF(NOT SYSCONFDIR)
    SET(SYSCONFDIR "/etc")
ENDIF(NOT SYSCONFDIR)

install(TARGETS resmtp
        RUNTIME DESTINATION ${SBINDIR})

install(FILES etc/resmtp.conf
        DESTINATION ${SYSCONFDIR}/resmtp/
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
