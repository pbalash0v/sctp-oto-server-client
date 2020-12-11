cmake_minimum_required(VERSION 3.17)

#################################
# Find deps
#################################
set(THREADS_PREFER_PTHREAD_FLAG ON) # Without this flag CMake may resort to just '-lpthread'
find_package(Threads REQUIRED)

find_package(Boost 1.65.0 REQUIRED system filesystem program_options)
#################################
# Define targets
#################################
foreach(TEST_NAME test1 test2 test4 test6 test7)

	add_executable(${TEST_NAME}
		${TEST_NAME}.cpp
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
		SCTP_OTO::sctp_client
		SCTP_OTO::sctp_common
		Boost::system
		Boost::filesystem
		Boost::program_options
	)
#	target_compile_definitions(${TEST_NAME} PRIVATE TEST_BUILD)

	add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)

	##########################################
	# Define test ordering, dependencies and properties
	##########################################
	set_tests_properties(test1 PROPERTIES TIMEOUT 1)
endforeach()

