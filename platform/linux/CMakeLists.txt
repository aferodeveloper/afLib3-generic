cmake_minimum_required (VERSION 2.8)

include_directories(../..)

add_library(afLib_c_linux
        linux_logger.c
        linux_uart.c
        linux_uart.h
        linux_utils.c
        )
