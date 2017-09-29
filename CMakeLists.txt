cmake_minimum_required(VERSION 3.0) # setting this is required
project(cice)            # this sets the project name

###############################################################################
## file globbing ##############################################################
###############################################################################

# These instructions search the directory tree when cmake is
# invoked and put all files that match the pattern in the variables 
# `sources` and `data`.
#file(GLOB_RECURSE sources      *.c *.h stun/*.c stun/*.h stun/usages/*.h stun/usages/*.c )
#file(GLOB sources_include include/*.h)
file(GLOB sources_include include/cice/*.h)
file(GLOB sources_top *.c *.h)
file(GLOB sources_stun stun/*.c stun/*.h)
file(GLOB sources_stun_usage stun/usages/*.h stun/usages/*.c )
file(GLOB_RECURSE sources_test src/test/*.cpp)
file(GLOB_RECURSE data resources/*)
# You can use set(sources src/main.cpp) etc if you don't want to
# use globbing to find files automatically.

###############################################################################
## target definitions #########################################################
###############################################################################

# The data is just added to the executable, because in some IDEs (QtCreator) 
# files are invisible when they are not explicitly part of the project.
#add_executable(example ${sources} ${data})
add_library(cice SHARED ${sources_top} ${sources_stun} ${sources_stun_usage})

# Just for example add some compiler flags.
target_compile_options(cice PUBLIC -g -Wall -I./)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(cice PUBLIC include .)

# This copies all resource files in the build directory.
# We need this, because we want to work with paths relative to the executable.
file(COPY ${data} DESTINATION resources)

###############################################################################
## dependencies ###############################################################
###############################################################################

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

# This defines the variables Boost_LIBRARIES that containts all library names
# that we need to link into the program.
#find_package(Boost 1.36.0 COMPONENTS filesystem system REQUIRED)

target_link_libraries(cice PUBLIC
  ${EVENT_LIBRARY}
  # here you can add any library dependencies
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

# All install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS cice DESTINATION lib)
install(
   FILES ${sources_include}
   DESTINATION include/cice
)
#install(
#   DIRECRORY ${CMAKE_SOURCE_DIR}/include
#   DESTINATION include
#   FILES_MATCHING PATTERN "*.h*"
#)

# This is basically a repeat of the file copy instruction that copies the
# resources in the build directory, but here we tell cmake that we want it
# in the package.
#install(DIRECTORY resources DESTINATION example_destination)

# Now comes everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here.
set(CPACK_PACKAGE_NAME "libcice")
set(CPACK_PACKAGE_VERSION "1.0.0")

# We don't want to split our program up into several incomplete pieces.
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)

