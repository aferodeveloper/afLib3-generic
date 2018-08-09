cmake_minimum_required (VERSION 2.8)

set(AFLIB_DIR ${CMAKE_SOURCE_DIR}/../../../..)
set(LINUX_PLATFORM_DIR ${AFLIB_DIR}/platform/linux)
set(PROFILE_INCLUDE_DIR ${AFLIB_DIR}/examples/afBlink/profile/afBlink)

project (afBlink_c)

include_directories(${AFLIB_DIR} ${PROFILE_INCLUDE_DIR} ${LINUX_PLATFORM_DIR} . )

add_subdirectory(${AFLIB_DIR} AFLIB)
add_subdirectory(${LINUX_PLATFORM_DIR} AFLIB_LINUX)

add_executable(afBlink linux_af_blink.c)

FIND_LIBRARY(COREFOUNDATION_LIBRARY CoreFoundation)

target_link_libraries(afBlink afLib_c_linux afLib_c ${COREFOUNDATION_LIBRARY})
