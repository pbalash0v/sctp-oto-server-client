cmake_minimum_required(VERSION 3.17)

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

add_library(sctp_server
	sctp_server.cpp
	server_event.cpp
	client_sctp_message.cpp
	client.cpp	
)
add_library(SCTP_OTO::sctp_server ALIAS sctp_server)
set_target_properties(sctp_server PROPERTIES OUTPUT_NAME sctp_server)
set_target_properties(sctp_server PROPERTIES POSITION_INDEPENDENT_CODE ON)


#target_compile_definitions(sctp_client PRIVATE
#
#)

# library public user interface
# this will transitively propagate to any lib user
target_include_directories(sctp_server PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>	
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(sctp_server PRIVATE
	SCTP_OTO::sctp_common
	usrsctp.a
)

target_link_libraries(sctp_server PUBLIC
	${OPENSSL_LIBRARIES}
)

# .so versioning
set_target_properties(sctp_server PROPERTIES
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
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/sctp_server
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	COMPONENT sctp_server_Dev
)

install(TARGETS sctp_server
	EXPORT sctp_server
	LIBRARY 
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT sctp_server_Runtime
		NAMELINK_COMPONENT sctp_server_Dev
	ARCHIVE
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT sctp_server_Dev
)


install(EXPORT sctp_server
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sctp_server
	COMPONENT sctp_server_Runtime
	COMPONENT sctp_server_Dev
	FILE sctp_serverConfig.cmake
	NAMESPACE SCTP_OTO::
)

export(EXPORT sctp_server)
