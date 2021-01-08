cmake_minimum_required(VERSION 3.10)

project(sctp_oto
	VERSION 0.1.0
	LANGUAGES CXX C
)

# cmake-gui configurable options
option(SCTP_OTO_BUILD_EXAMPLES "Build examples" ON)
option(SCTP_OTO_BUILD_TESTS "Build tests" OFF)
option(SCTP_OTO_BUILD_PYTHON_BINDINGS "Build Python bindings" OFF)

# append local cmake dir to include path for cmake modules
list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	if("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
		message(FATAL_ERROR "In-source builds are not allowed.")
	endif("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")

	# Be specific by assuming default build type is "debug" if no build type was explicitly set
	if(CMAKE_BUILD_TYPE STREQUAL "")
		set(CMAKE_BUILD_TYPE "Debug")
	endif()

	# Set build tree output directories for convenience
	if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
		set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)
		set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)
		set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
	endif()

endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")


include(pull_3rd_pty)


# sctp itself
add_subdirectory(src)

# Enabling test
if(SCTP_OTO_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)
endif()
