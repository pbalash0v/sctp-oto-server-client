cmake_minimum_required(VERSION 3.10)


#################################
# Define targets	
#################################
add_library(gopt OBJECT
	gopt.c
	gopt-errors.c
)
add_library(SCTP_OTO::gopt ALIAS gopt)
set_target_properties(gopt PROPERTIES POSITION_INDEPENDENT_CODE ON)


# library public user interface
# this will transitively propagate to any lib user
target_include_directories(gopt PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
