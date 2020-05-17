cmake_minimum_required(VERSION 3.17)


#################################
# Define targets	
#################################
set(CMAKE_INSTALL_RPATH $ORIGIN $ORIGIN/../lib)

add_library(gopt
	gopt.c
	gopt-errors.c
	gopt-usage.c
)
add_library(SCTP_OTO::gopt ALIAS gopt)
set_target_properties(gopt PROPERTIES OUTPUT_NAME gopt)
set_target_properties(gopt PROPERTIES POSITION_INDEPENDENT_CODE ON)


# library public user interface
# this will transitively propagate to any lib user
target_include_directories(gopt PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# .so versioning
set_target_properties(sctp_client PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)
