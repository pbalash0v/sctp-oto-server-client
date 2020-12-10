cmake_minimum_required(VERSION 3.17)

add_subdirectory(lib)

if(SCTP_OTO_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()



