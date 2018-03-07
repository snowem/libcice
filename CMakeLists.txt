cmake_minimum_required(VERSION 3.0) # setting this is required
project(cice)            # this sets the project name

## file globbing ##############################################################
file(GLOB sources_include include/cice)
file(GLOB sources_top *.c *.h)
file(GLOB sources_stun stun/*.c stun/*.h)
file(GLOB sources_stun_usage stun/usages/*.h stun/usages/*.c )
file(GLOB_RECURSE sources_test src/test/*.cpp)
file(GLOB_RECURSE data resources/*)

## target definitions #########################################################
add_library(cice SHARED ${sources_top} ${sources_stun} ${sources_stun_usage})
add_library(cice_static STATIC ${sources_top} ${sources_stun} ${sources_stun_usage})

target_compile_options(cice PUBLIC -g -Wall -DUSE_LIBEVENT2)
target_compile_options(cice_static PUBLIC -g -Wall -DUSE_LIBEVENT2)
target_include_directories(cice PUBLIC include)
target_include_directories(cice_static PUBLIC include)

file(COPY ${data} DESTINATION resources)

## dependencies ###############################################################
# Find Libevent
# http://monkey.org/~provos/libevent/
#
# Once done, this will define:
#
#  Event_FOUND - system has Event
#  Event_INCLUDE_DIRS - the Event include directories
#  Event_LIBRARIES - link these to use Event
#
if (EVENT_INCLUDE_DIR AND EVENT_LIBRARY)
  # Already in cache, be silent
  set(EVENT_FIND_QUIETLY TRUE)
endif (EVENT_INCLUDE_DIR AND EVENT_LIBRARY)

find_path(EVENT_INCLUDE_DIR event.h
  PATHS /usr/include
  PATH_SUFFIXES event
)

find_library(EVENT_LIBRARY
  NAMES event
  PATHS /usr/lib /usr/local/lib
)

set(EVENT_LIBRARIES ${EVENT_LIBRARY} )

add_definitions(-DLIBNET_LIL_ENDIAN)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(EVENT
  DEFAULT_MSG
  EVENT_INCLUDE_DIR
  EVENT_LIBRARIES
)

mark_as_advanced(EVENT_INCLUDE_DIR EVENT_LIBRARY)

target_link_libraries(cice PUBLIC
  ${EVENT_LIBRARY}
)

###############################################################################
## testing ####################################################################
###############################################################################

# This is for our testing framework,
# we don't add REQUIRED because it's just for testing.
# People who might want to build the project to use it should not be required
# to install testing dependencies.
#find_package(GTest)

#if(GTEST_FOUND)
#  add_executable(unit_tests ${sources_test} ${sources})
#
#  # This define is added to prevent collision with the main.
#  # It might be better solved by not adding the source with the main to the
#  # testing target.
#  target_compile_definitions(unit_tests PUBLIC UNIT_TESTS)
#
#  # This allows us to use the executable as a link library, and inherit all 
#  # linker options and library dependencies from it, by simply adding it as dependency.
#  set_target_properties(example PROPERTIES ENABLE_EXPORTS on)
#
#  target_link_libraries(unit_tests PUBLIC
#    ${GTEST_BOTH_LIBRARIES}
#    example
#  )
#
#  target_include_directories(unit_tests PUBLIC
#    ${GTEST_INCLUDE_DIRS} # doesn't do anything on linux
#  )
#  
#endif()

###############################################################################
## packaging ##################################################################
###############################################################################
install(TARGETS cice DESTINATION lib)
install(
  DIRECTORY ${sources_include}
  DESTINATION include
)

set(CPACK_PACKAGE_NAME "libcice")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)

