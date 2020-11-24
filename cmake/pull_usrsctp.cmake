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

#
# Define usrstcp target
#
# Hack to make it work, otherwise INTERFACE_INCLUDE_DIRECTORIES will not be propagated
file(MAKE_DIRECTORY ${LOCAL_BUILD_ARTIFACTS_DIR}/include/)

add_library(usrsctp_static STATIC IMPORTED GLOBAL)

set_target_properties(usrsctp_static PROPERTIES
	IMPORTED_LOCATION ${LOCAL_BUILD_ARTIFACTS_DIR}/lib/libusrsctp.a
)
target_include_directories(usrsctp_static SYSTEM INTERFACE ${LOCAL_BUILD_ARTIFACTS_DIR}/include/)

add_library(USRSCTP::static ALIAS usrsctp_static)
