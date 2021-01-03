ExternalProject_Add(spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog
	GIT_TAG origin/v1.x
	GIT_PROGRESS ON

	UPDATE_COMMAND ""
	INSTALL_DIR ${LOCAL_BUILD_ARTIFACTS_DIR}
	CMAKE_ARGS -DCMAKE_PREFIX_PATH:PATH=<INSTALL_DIR>
				-DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
				-DCMAKE_BUILD_TYPE:STRING=Release
				-DCMAKE_POSITION_INDEPENDENT_CODE=ON
)

ExternalProject_Get_property(spdlog SOURCE_DIR)

add_library(libspdlog INTERFACE)
target_include_directories(libspdlog SYSTEM INTERFACE
	$<BUILD_INTERFACE:${SOURCE_DIR}/include>
)
target_compile_features(libspdlog INTERFACE
	cxx_std_17
)
