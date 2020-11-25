cmake_minimum_required(VERSION 3.17)

#################################
# Find deps
#################################
set(THREADS_PREFER_PTHREAD_FLAG ON) # Without this flag CMake may resort to just '-lpthread'
find_package(Threads REQUIRED)

find_package(Boost 1.65.0 REQUIRED system filesystem)
#################################
# Define targets
#################################
set(TEST_NAME simple)

add_executable(${TEST_NAME}
	test1.cpp
)

set_target_properties(${TEST_NAME} PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
)


target_compile_options(${TEST_NAME} PRIVATE
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic -Werror>
)

target_link_libraries(${TEST_NAME} PRIVATE
	Threads::Threads
	SCTP_OTO::sctp_server
	Boost::system
	Boost::filesystem
)


add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)


##########################################
# Define test ordering, dependencies and properties
##########################################
set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT 1)
