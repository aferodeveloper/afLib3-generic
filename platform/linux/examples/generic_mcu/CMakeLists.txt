cmake_minimum_required (VERSION 3.2)

set(AFLIB_DIR ${CMAKE_SOURCE_DIR}/../../../..)
set(LINUX_PLATFORM_DIR ${AFLIB_DIR}/platform/linux)

project (generic_mcu)

include_directories(${AFLIB_DIR} ${LINUX_PLATFORM_DIR} . )

add_subdirectory(${AFLIB_DIR} AFLIB)
add_subdirectory(${LINUX_PLATFORM_DIR} AFLIB_LINUX)

add_executable(generic_mcu generic_mcu.c)

target_link_libraries(generic_mcu afLib_c_linux afLib_c)
