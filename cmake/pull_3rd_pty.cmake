############################################################
# Pull and build local dependencies
############################################################
include(ExternalProject)
include(FetchContent)

set(LOCAL_BUILD_ARTIFACTS_DIR ${CMAKE_BINARY_DIR}/build_artifacts)

include_directories(BEFORE ${LOCAL_BUILD_ARTIFACTS_DIR}/include)
link_directories(BEFORE ${LOCAL_BUILD_ARTIFACTS_DIR}/lib)


#
# pull components
#
include(pull_fmt)
include(pull_spdlog)
include(pull_usrsctp)
############################################################

