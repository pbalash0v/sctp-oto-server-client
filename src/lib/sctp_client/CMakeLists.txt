cmake_minimum_required(VERSION 3.10)

# this will just define vars like CMAKE_INSTALL_<dir>:
# CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_LIBDIR etc
include(GNUInstallDirs)

#################################
# Find deps
#################################
find_package(OpenSSL 1.1.1 REQUIRED)

#################################
# Define targets	
#################################
set(CMAKE_INSTALL_RPATH $ORIGIN $ORIGIN/../lib)
set(TARGET_NAME sctp_client)

add_library(${TARGET_NAME})
target_sources(${TARGET_NAME} PRIVATE
	${TARGET_NAME}.cpp
)

add_library(SCTP_OTO::${TARGET_NAME} ALIAS ${TARGET_NAME})
set_target_properties(${TARGET_NAME} PROPERTIES OUTPUT_NAME ${TARGET_NAME})

# Properties
set_target_properties(${TARGET_NAME} PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
	POSITION_INDEPENDENT_CODE ON
)

#target_compile_definitions(${TARGET_NAME} PRIVATE
#
#)

# library public user interface
# this will transitively propagate to any lib user
target_include_directories(${TARGET_NAME} PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(${TARGET_NAME} PRIVATE
	$<BUILD_INTERFACE:SCTP_OTO::sctp_common>
	$<BUILD_INTERFACE:USRSCTP::static>
)

target_link_libraries(${TARGET_NAME} PUBLIC
	${OPENSSL_LIBRARIES}
)

# .so versioning
set_target_properties(${TARGET_NAME} PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)


#################################
# Install
#################################

#
# It is supposed by CMake that we use PUBLIC_HEADER for public lib header, but:
# PUBLIC_HEADER is the proper way only in very simple cases.
# As soon as you have multiple subdirectories for the headers it does no longer work,
# as CMake flattens the hierarchy and puts all headers into the same directory.
# set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${TARGET_PUBLIC_HEADERS}")
#
# those are library public API interface used by its components
# should go to dev package
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/${TARGET_NAME}
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	COMPONENT ${TARGET_NAME}_Dev
)

install(TARGETS ${TARGET_NAME} sctp_common
	EXPORT ${TARGET_NAME}
	LIBRARY 
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT ${TARGET_NAME}_Runtime
		NAMELINK_COMPONENT ${TARGET_NAME}_Dev
	ARCHIVE
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT ${TARGET_NAME}_Dev
)


install(EXPORT ${TARGET_NAME}
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${TARGET_NAME}
	COMPONENT ${TARGET_NAME}_Runtime
	COMPONENT ${TARGET_NAME}_Dev
	FILE ${TARGET_NAME}Config.cmake
	NAMESPACE SCTP_OTO::
)

export(EXPORT ${TARGET_NAME})
