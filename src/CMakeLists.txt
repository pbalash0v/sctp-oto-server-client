cmake_minimum_required(VERSION 3.10)

add_subdirectory(lib)

if(SCTP_OTO_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()

if(SCTP_OTO_BUILD_PYTHON_BINDINGS)
	add_subdirectory(python)
endif()
