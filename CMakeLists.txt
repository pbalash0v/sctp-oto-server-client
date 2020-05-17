cmake_minimum_required(VERSION 3.17)

project(sctp_oto_server_and_client
	VERSION 0.1.0
	LANGUAGES CXX C
)

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

############################################################
# Pull and build local dependencies
############################################################
include(ExternalProject)

set(LOCAL_BUILD_ARTIFACTS_DIR ${CMAKE_BINARY_DIR}/build_artifacts)

ExternalProject_Add(usrsctp
	GIT_REPOSITORY https://github.com/sctplab/usrsctp
	GIT_TAG a05154264872ec8e5d4143ac841a306f54ace231
#	GIT_TAG origin/master
	GIT_PROGRESS ON	
	INSTALL_DIR ${LOCAL_BUILD_ARTIFACTS_DIR}
	CONFIGURE_COMMAND cd <SOURCE_DIR> && <SOURCE_DIR>/bootstrap && <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>;--with-pic
	BUILD_COMMAND cd <SOURCE_DIR> && make
	INSTALL_COMMAND cd <SOURCE_DIR> && make	install
)

ExternalProject_Add(spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog
	GIT_TAG origin/v1.x
	INSTALL_DIR ${LOCAL_BUILD_ARTIFACTS_DIR}
	CMAKE_ARGS -DCMAKE_PREFIX_PATH=<INSTALL_DIR>
				-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
				-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
				-DCMAKE_POSITION_INDEPENDENT_CODE=ON
)


# Force "protobuf_c install" before "natsc build"
# Argument mnemonic is: "natsc configure DEPENDS ON protobuf_c-install
#ExternalProject_Add_StepDependencies(natsc configure protobuf_c)
include_directories(BEFORE ${LOCAL_BUILD_ARTIFACTS_DIR}/include)
link_directories(BEFORE ${LOCAL_BUILD_ARTIFACTS_DIR}/lib)
############################################################

# sctp itself
add_subdirectory(src)

# only package if we are root project, because CPack can only be called once per cmake build
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
#	add_subdirectory(packaging) # include(CPack) will happen in here
endif()
