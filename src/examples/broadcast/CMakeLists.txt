cmake_minimum_required(VERSION 3.17)

#################################
# Find deps
#################################
set(THREADS_PREFER_PTHREAD_FLAG ON) # Without this flag CMake may resort to just '-lpthread'
find_package(Threads REQUIRED)


#################################
# Define targets	
#################################
set(CMAKE_INSTALL_RPATH $ORIGIN $ORIGIN/../lib)

# client
configure_file(ex_bcast_version.h.in ex_bcast_version.h @ONLY)

add_executable(ex_broadcast_client
	client_main.cpp
	tui/simple_tui.cpp
)
set_target_properties(ex_broadcast_client PROPERTIES OUTPUT_NAME ex_broadcast_client)

target_include_directories(ex_broadcast_client PRIVATE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/tui/include>	
)
target_include_directories(ex_broadcast_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}") # versioning

target_link_libraries(ex_broadcast_client PRIVATE
	Threads::Threads
	libspdlog
	SCTP_OTO::sctp_common
	SCTP_OTO::sctp_client
	SCTP_OTO::gopt
)

# server
add_executable(ex_broadcast_server
	broadcaster.cpp
	server_main.cpp
)
set_target_properties(ex_broadcast_server PROPERTIES OUTPUT_NAME ex_broadcast_server)

target_include_directories(ex_broadcast_server PRIVATE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_include_directories(ex_broadcast_server PRIVATE "${CMAKE_CURRENT_BINARY_DIR}") # versioning

target_link_libraries(ex_broadcast_server PRIVATE
	Threads::Threads
	libspdlog
	SCTP_OTO::sctp_common
	SCTP_OTO::sctp_server
	SCTP_OTO::gopt
)
