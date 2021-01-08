cmake_minimum_required(VERSION 3.17)

message(STATUS "Standby, pulling pybind11...")

FetchContent_Declare(pybind
	GIT_REPOSITORY https://github.com/pybind/pybind11.git
	GIT_TAG origin/master
	GIT_PROGRESS ON
)
FetchContent_MakeAvailable(pybind)

pybind11_add_module(pysctp module.cpp)

set_target_properties(pysctp PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
	POSITION_INDEPENDENT_CODE ON
)

target_link_libraries(pysctp PUBLIC
	SCTP_OTO::sctp_server
)
