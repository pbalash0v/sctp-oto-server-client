cmake_minimum_required(VERSION 3.17)

project(sctp_oto_server_and_client
	VERSION 0.1.0
	LANGUAGES CXX C
)

# cmake-gui configurable options
option(SCTP_OTO_BUILD_EXAMPLES "Build examples" ON)
option(SCTP_OTO_BUILD_SH_LIBS "Build shared libs" ON)

# handle externally set BUILD_SHARED_LIBS
if(NOT DEFINED BUILD_SHARED_LIBS AND SCTP_OTO_BUILD_SH_LIBS)
	set(BUILD_SHARED_LIBS ON)
endif()


# Be specific by assuming default build type is "debug" if no build type was explicitly set
if(CMAKE_BUILD_TYPE STREQUAL "")
	set(CMAKE_BUILD_TYPE "Debug")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# strictly define used C++ standart
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# append local cmake dir to include path for cmake modules
list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(pull_3rd_pty)

# Set build tree output directories
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/software/lib)
	set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/software/lib)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/software/bin)
endif()

# sctp itself
add_subdirectory(src)

# only package if we are root project, because CPack can only be called once per cmake build
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
#	add_subdirectory(packaging) # include(CPack) will happen in here
endif()
