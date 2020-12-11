cmake_minimum_required(VERSION 3.17)

# this will just define vars like CMAKE_INSTALL_<dir>:
# CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_LIBDIR etc
include(GNUInstallDirs)

#################################
# Find deps
#################################
find_package(OpenSSL 1.1.1 REQUIRED)

find_package(Boost 1.65.0 REQUIRED system filesystem program_options)
#################################
# Define targets	
#################################
set(CMAKE_INSTALL_RPATH $ORIGIN $ORIGIN/../lib)

add_library(sctp_common
	ssl_h.cpp
)
add_library(SCTP_OTO::sctp_common ALIAS sctp_common)
set_target_properties(sctp_common PROPERTIES OUTPUT_NAME sctp_common)
set_target_properties(sctp_common PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Properties
set_target_properties(sctp_common PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
)

#target_compile_definitions(sctp_client PRIVATE
#
#)

# library public user interface
# this will transitively propagate to any lib user
target_include_directories(sctp_common PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

#target_link_libraries(sctp_common PRIVATE
#	usrsctp.a
#)

target_link_libraries(sctp_common PUBLIC
	${OPENSSL_LIBRARIES}
	Boost::boost
	Boost::system
	Boost::filesystem
)

# .so versioning
set_target_properties(sctp_common PROPERTIES
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
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/sctp_common
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	COMPONENT sctp_common_Dev
)

install(TARGETS sctp_common
	EXPORT sctp_common
	LIBRARY 
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT sctp_common_Runtime
		NAMELINK_COMPONENT sctp_common_Dev
	ARCHIVE
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT sctp_common_Dev
)


install(EXPORT sctp_common
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sctp_common
	COMPONENT sctp_common_Runtime
	COMPONENT sctp_common_Dev
	FILE sctp_commonConfig.cmake
	NAMESPACE SCTP_OTO::
)

export(EXPORT sctp_common)
