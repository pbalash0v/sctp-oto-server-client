############################################################
# Pull and build local dependencies
############################################################
include(ExternalProject)
include(FetchContent)

set(LOCAL_BUILD_ARTIFACTS_DIR ${CMAKE_BINARY_DIR}/build_artifacts)

ExternalProject_Add(usrsctp
	GIT_REPOSITORY https://github.com/sctplab/usrsctp
#	GIT_TAG a05154264872ec8e5d4143ac841a306f54ace231
	GIT_TAG origin/master
	GIT_PROGRESS ON
	INSTALL_DIR ${LOCAL_BUILD_ARTIFACTS_DIR}
	CMAKE_ARGS -DCMAKE_PREFIX_PATH=<INSTALL_DIR>
				-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
				-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
				-DCMAKE_POSITION_INDEPENDENT_CODE=ON
				-Dsctp_werror=OFF
				-Dsctp_build_programs=OFF
)

ExternalProject_Add(spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog
	GIT_TAG origin/v1.x
	GIT_PROGRESS ON
	INSTALL_DIR ${LOCAL_BUILD_ARTIFACTS_DIR}
	CMAKE_ARGS -DCMAKE_PREFIX_PATH=<INSTALL_DIR>
				-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
				-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
				-DCMAKE_POSITION_INDEPENDENT_CODE=ON
)

FetchContent_Declare(fmt
	GIT_REPOSITORY https://github.com/fmtlib/fmt.git
	GIT_TAG        6.2.1
	GIT_PROGRESS ON  
)
FetchContent_MakeAvailable(fmt)
FetchContent_GetProperties(fmt)
if(NOT fmt_POPULATED)
  FetchContent_Populate(fmt)
  add_subdirectory(${fmt_SOURCE_DIR} ${fmt_BINARY_DIR})
endif()



include_directories(BEFORE ${LOCAL_BUILD_ARTIFACTS_DIR}/include)
link_directories(BEFORE ${LOCAL_BUILD_ARTIFACTS_DIR}/lib)
############################################################
