cmake_minimum_required(VERSION 3.10)


#################################
# Find deps
#################################
find_package(OpenSSL 1.1.1 REQUIRED)

find_package(Boost 1.65.0 REQUIRED system filesystem program_options)

#################################
# Define targets	
#################################
set(CMAKE_INSTALL_RPATH $ORIGIN $ORIGIN/../lib)

add_library(sctp_common OBJECT
	ssl_h.cpp
)
add_library(SCTP_OTO::sctp_common ALIAS sctp_common)

# Properties
set_target_properties(sctp_common PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
	POSITION_INDEPENDENT_CODE ON
)


# library public user interface
# this will transitively propagate to any lib user
target_include_directories(sctp_common PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(sctp_common PRIVATE
	Boost::boost
)

target_link_libraries(sctp_common PUBLIC
	${OPENSSL_LIBRARIES}
	Boost::system
	Boost::filesystem
)
