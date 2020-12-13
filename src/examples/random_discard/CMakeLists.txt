cmake_minimum_required(VERSION 3.10)

#################################
# Find deps
#################################
set(THREADS_PREFER_PTHREAD_FLAG ON) # Without this flag CMake may resort to just '-lpthread'
find_package(Threads REQUIRED)

find_package(Boost 1.65.0 REQUIRED system filesystem program_options)
#################################
# Define targets	
#################################
set(CMAKE_INSTALL_RPATH $ORIGIN $ORIGIN/../lib)

# client
add_executable(ex_discard_client
	client_main.cpp
	traffic_stats.cpp
	rand_data_gen.cpp
)
set_target_properties(ex_discard_client PROPERTIES OUTPUT_NAME discard_client)

target_include_directories(ex_discard_client PRIVATE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_include_directories(ex_discard_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

target_link_libraries(ex_discard_client PRIVATE
	Threads::Threads
	libspdlog
	SCTP_OTO::sctp_common
	SCTP_OTO::sctp_client
	SCTP_OTO::gopt
	Boost::program_options
)

# server
add_executable(ex_discard_server
	server_main.cpp
)
set_target_properties(ex_discard_server PROPERTIES OUTPUT_NAME discard_server)

target_include_directories(ex_discard_server PRIVATE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_include_directories(ex_discard_server PRIVATE "${CMAKE_CURRENT_BINARY_DIR}") # versioning

target_link_libraries(ex_discard_server PRIVATE
	Threads::Threads
	libspdlog
	SCTP_OTO::sctp_common
	SCTP_OTO::sctp_server
	SCTP_OTO::sctp_common
	Boost::program_options
)
